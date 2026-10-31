package db

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Yeadear/qqdump/cipher"
	"github.com/Yeadear/qqdump/model"
)

// pageReader 是 StreamDB 对"逐页解密"的最小依赖。用接口而非具体类型，
// 方便用假实现做单元测试（见 stream_test.go）。
type pageReader interface {
	DecryptPage(pgno uint32) ([]byte, error)
	UsableSize() int
	Close() error
}

// StreamDB 是 nt_msg.db 的流式只读视图：不落明文、不整库载入，
// 读取时按需逐页解密并解析 b-tree。它直接解析 SQLite 文件格式，因此不需要
// 把整个库解密成明文文件，也不需要 database/sql 把整张表 SELECT 进内存。
type StreamDB struct {
	dec      pageReader
	usable   int
	pageSize int
	pages    uint32 // 文件页数，用于挡越界指针；0 表示未知
	skipped  int    // 遍历时跳过的 cell 数（坏页/坏指针/坏 payload）
	tables   map[string]tableInfo
}

type tableInfo struct {
	name     string
	rootpage uint32
	cols     []string // CREATE TABLE 的列名顺序
	chatType int
}

// OpenEncryptedStream 打开一个加密的 nt_msg.db（含 1024 字节自定义头），
// 不解密到磁盘、不整库载入，仅在探测阶段读取少量页面。
func OpenEncryptedStream(src, key string, tolerant bool) (*StreamDB, error) {
	dec, err := cipher.NewDecrypter(src, key, tolerant)
	if err != nil {
		return nil, err
	}
	s := &StreamDB{dec: dec, usable: dec.UsableSize(), pageSize: dec.PageSize(), pages: dec.PageCount()}
	if err := s.probe(); err != nil {
		dec.Close()
		return nil, err
	}
	return s, nil
}

// Close 释放底层资源。
func (s *StreamDB) Close() error { return s.dec.Close() }

// Tables 返回库中存在的消息表名。
func (s *StreamDB) Tables() []string {
	out := make([]string, 0, len(s.tables))
	for name := range s.tables {
		out = append(out, name)
	}
	return out
}

// probe 读取 sqlite_master，登记消息表及其根页与列。
func (s *StreamDB) probe() error {
	s.tables = map[string]tableInfo{}
	var rows []masterRow
	err := s.walkTable(1, func(_ int64, payload []byte) error {
		r, e := parseMasterRow(payload)
		if e != nil {
			return nil // 跳过解析失败的 master 行
		}
		rows = append(rows, r)
		return nil
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.typ != "table" {
			continue
		}
		var ct int
		switch r.name {
		case TableC2C:
			ct = model.ChatC2C
		case TableGroup:
			ct = model.ChatGroup
		default:
			continue
		}
		s.tables[r.name] = tableInfo{
			name:     r.name,
			rootpage: uint32(r.rootpage),
			cols:     parseColumnNames(r.sql),
			chatType: ct,
		}
	}
	if len(s.tables) == 0 {
		return fmt.Errorf("db: 库里没有找到 %s 或 %s，这不是一个 nt_msg 库", TableC2C, TableGroup)
	}
	return nil
}

// StreamMessages 流式读取某表的消息，对每条消息回调 cb。
// filter 支持按 PeerUIN / SessionID / 时间范围 / 数量上限过滤（按时间正序）。
func (s *StreamDB) StreamMessages(table string, f Filter, cb func(model.Message) error) error {
	ti, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("db: 未知表 %s", table)
	}
	count := 0
	return s.walkTable(ti.rootpage, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return nil // 跳过坏行
		}
		vals := mapColumns(ti.cols, cols)
		m := fill(vals, ti.chatType)
		if !matchFilter(m, f) {
			return nil
		}
		if f.Limit > 0 && count >= f.Limit {
			return nil
		}
		count++
		return cb(m)
	})
}

// StreamSessions 流式收集某表的会话概要（按 40030 去重）。
// 用于先列出会话、再逐个导出；它只遍历一遍 b-tree，内存仅存会话概要。
func (s *StreamDB) StreamSessions(table string, cb func(Session) error) error {
	ti, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("db: 未知表 %s", table)
	}
	type acc struct {
		peerUIN  int64
		peerUID  string
		chatType int
		name     string
		count    int64
	}
	m := map[int64]*acc{}
	err := s.walkTable(ti.rootpage, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return nil
		}
		vals := mapColumns(ti.cols, cols)
		mm := fill(vals, ti.chatType)
		a := m[mm.PeerUIN]
		if a == nil {
			a = &acc{peerUIN: mm.PeerUIN, peerUID: mm.PeerUID, chatType: ti.chatType}
			m[mm.PeerUIN] = a
		}
		if mm.SenderName != "" {
			a.name = mm.SenderName
		}
		a.count++
		return nil
	})
	if err != nil {
		return err
	}
	for _, a := range m {
		if err := cb(Session{
			Table:    table,
			PeerUIN:  a.peerUIN,
			PeerUID:  a.peerUID,
			ChatType: a.chatType,
			Name:     a.name,
			Count:    a.count,
		}); err != nil {
			return err
		}
	}
	return nil
}

// StreamSessionMessages 流式读取某一个会话（按 40030 匹配）的消息，
// 边扫描边回调，内存里只有"当前窗口 + 单条消息"。
//
// 输出按时间升序：b-tree 的物理顺序并不保证时间序（同一会话里 web 端发来的
// 消息 rowid 可能比手机端更晚却时间更早），所以这里用固定大小的窗口缓冲，
// 攒满 window 条就排序回调一次，最后一个不满的窗口在结尾回调。这样既保证
// 顺序，又把内存钉在 window 条消息上，与库大小无关。
func (s *StreamDB) StreamSessionMessages(table string, peer int64, f Filter, cb func(model.Message) error) error {
	return s.StreamSessionMessagesWindow(table, peer, f, SortWindow, cb)
}

// SortWindow 是单会话流式排序窗口的默认大小。窗口越大顺序越准、内存越多；
// 4096 条大约几 MB，对聊天记录足够（同一会话内时间错位通常只跨几十条）。
const SortWindow = 4096

// FanoutWindow 是单遍多会话扇出时每个会话的排序窗口。
//
// 扇出要同时为所有会话保留窗口，内存约等于「会话数 × 窗口」。一个 660 万条的
// 账号有 1600 多个会话，用 4096 会吃到 2.9GB；512 条已足够纠正同会话内的时间
// 错位（实测错位通常只有几十条），内存降到几百 MB。
const FanoutWindow = 512

// StreamSessionMessagesWindow 是 StreamSessionMessages 的可调窗口版本。
func (s *StreamDB) StreamSessionMessagesWindow(table string, peer int64, f Filter, window int, cb func(model.Message) error) error {
	ti, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("db: 未知表 %s", table)
	}
	if window <= 0 {
		window = SortWindow
	}
	f.PeerUIN = peer

	buf := make([]model.Message, 0, window)
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		sort.SliceStable(buf, func(i, j int) bool {
			if buf[i].Timestamp != buf[j].Timestamp {
				return buf[i].Timestamp < buf[j].Timestamp
			}
			return buf[i].ID < buf[j].ID
		})
		for _, m := range buf {
			if err := cb(m); err != nil {
				return err
			}
		}
		buf = buf[:0]
		return nil
	}

	count := 0
	err := s.walkTable(ti.rootpage, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return nil
		}
		vals := mapColumns(ti.cols, cols)
		m := fill(vals, ti.chatType)
		if !matchFilter(m, f) {
			return nil
		}
		if f.Limit > 0 && count >= f.Limit {
			return errStopScan
		}
		count++
		buf = append(buf, m)
		if len(buf) >= window {
			return flush()
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return err
	}
	return flush()
}

// errStopScan 由回调返回以提前结束遍历（达到 Limit 时）。
var errStopScan = errors.New("db: 扫描结束")

// FanoutSink 是单遍多会话扇出的接收端：每个会话一个。
//
// 一次遍历把整张表的所有会话消息按会话分发出去，避免"每个会话扫一遍全表"
// ——6.6GB 的库有 200 多个会话时，N+1 次全表扫描要跑几个小时。
type FanoutSink struct {
	// Peer 是该 sink 只关心的会话（消息的 40030 等于它）。
	Peer int64
	// Conversation 在该会话收到第一条消息时调用一次，用于打开输出文件。
	Conversation func() error
	// Message 接收已按时间升序排好的消息。
	Message func(model.Message) error
	// Done 在该会话的最后一个窗口刷出后调用一次。
	Done func(count int) error
}

// StreamFanout 单遍遍历 table，把消息按 PeerUIN 分发给 sinks 里对应的会话。
//
// 内存模型：每个 sink 一个独立的排序窗口（默认 SortWindow 条），窗满即刷出。
// 因此总内存 ≈ 会话数 × 窗口大小；会话多时用 window 收紧。
// 找不到对应 sink 的消息直接丢弃（不缓存），所以内存不会随库大小增长。
func (s *StreamDB) StreamFanout(table string, sinks []*FanoutSink, f Filter, window int) error {
	ti, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("db: 未知表 %s", table)
	}
	if window <= 0 {
		window = SortWindow
	}
	if len(sinks) == 0 {
		return nil
	}

	type state struct {
		sink  *FanoutSink
		buf   []model.Message
		count int
		open  bool
	}
	// 按 PeerUIN 索引，避免每条消息线性找 sink。
	byPeer := make(map[int64]*state, len(sinks))
	for _, sk := range sinks {
		byPeer[sk.Peer] = &state{sink: sk, buf: make([]model.Message, 0, window)}
	}

	flush := func(st *state) error {
		if len(st.buf) == 0 {
			return nil
		}
		sort.SliceStable(st.buf, func(i, j int) bool {
			if st.buf[i].Timestamp != st.buf[j].Timestamp {
				return st.buf[i].Timestamp < st.buf[j].Timestamp
			}
			return st.buf[i].ID < st.buf[j].ID
		})
		if !st.open && st.sink.Conversation != nil {
			st.open = true
			if err := st.sink.Conversation(); err != nil {
				return err
			}
		}
		for _, m := range st.buf {
			if st.sink.Message != nil {
				if err := st.sink.Message(m); err != nil {
					return err
				}
			}
		}
		st.buf = st.buf[:0]
		return nil
	}

	err := s.walkTable(ti.rootpage, func(_ int64, payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return nil
		}
		vals := mapColumns(ti.cols, cols)
		m := fill(vals, ti.chatType)
		// 先按会话筛，再做时间等过滤：不关心的消息连对象都不必造全。
		st, ok := byPeer[m.PeerUIN]
		if !ok {
			return nil
		}
		ff := f
		ff.PeerUIN = m.PeerUIN
		if !matchFilter(m, ff) {
			return nil
		}
		if f.Limit > 0 && st.count >= f.Limit {
			return nil
		}
		st.count++
		st.buf = append(st.buf, m)
		if len(st.buf) >= window {
			return flush(st)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, sk := range sinks {
		st := byPeer[sk.Peer]
		if err := flush(st); err != nil {
			return err
		}
		if st.count > 0 && st.sink.Done != nil {
			if err := st.sink.Done(st.count); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkTable 在遇到 errStopScan 时视为正常结束。

// ---- SQLite 文件格式解析 ----

// walkTable 遍历一个表 b-tree（从 root 页开始），对每一个 leaf cell 调用 cb。
func (s *StreamDB) walkTable(root uint32, cb func(rowid int64, payload []byte) error) error {
	q := []uint32{root}
	visited := make(map[uint32]bool, 64)
	for len(q) > 0 {
		pgno := q[0]
		q = q[1:]
		if visited[pgno] {
			continue // 指针读坏时可能自指，防死循环
		}
		visited[pgno] = true
		if err := s.walkPage(pgno, &q, cb); err != nil {
			if errors.Is(err, errStopScan) {
				return nil
			}
			return err
		}
	}
	return nil
}

// walkPage 解密并解析一页；interior 页把子页号追加到 q，leaf 页逐个回调。
func (s *StreamDB) walkPage(pgno uint32, q *[]uint32, cb func(int64, []byte) error) error {
	content, err := s.dec.DecryptPage(pgno)
	if err != nil {
		// 坏页（HMAC 校验失败）或越界页号都只影响一条子树，跳过继续，
		// 否则一格损坏就能让整张表读不出来。
		if errors.Is(err, cipher.ErrCorruptPage) || errors.Is(err, cipher.ErrPageOutOfRange) {
			return nil
		}
		return err
	}
	hdr := 0
	if pgno == 1 {
		if !bytes.HasPrefix(content, []byte("SQLite format 3\x00")) {
			return fmt.Errorf("db: 第 1 页不是 SQLite 库")
		}
		hdr = 100 // 数据库头占据 page 1 前 100 字节
	}
	if len(content) < hdr+8 {
		return nil
	}
	pageType := content[hdr]
	switch pageType {
	case 0x0d: // leaf table
		return s.walkLeaf(content, hdr, cb)
	case 0x05: // interior table
		return s.walkInterior(content, hdr, q, cb)
	default:
		return fmt.Errorf("db: 第 %d 页类型 %#x 不是表 b-tree 页", pgno, pageType)
	}
}

func (s *StreamDB) walkLeaf(content []byte, hdr int, cb func(int64, []byte) error) error {
	nCells := int(binary.BigEndian.Uint16(content[hdr+3 : hdr+5]))
	if hdr+8+2*nCells > len(content) {
		return nil
	}
	cellPtrs := content[hdr+8 : hdr+8+2*nCells]
	for i := 0; i < nCells; i++ {
		ptr := int(binary.BigEndian.Uint16(cellPtrs[2*i : 2*i+2]))
		if ptr < hdr || ptr >= len(content) {
			s.skipped++
			continue
		}
		cell := content[ptr:]
		plen, n1, err := readVarint(cell, 0)
		if err != nil {
			s.skipped++
			continue
		}
		rowid, n2, err := readVarint(cell, n1)
		if err != nil {
			s.skipped++
			continue
		}
		payload, err := s.localPayload(cell[n1+n2:], int(plen))
		if err != nil {
			// 单条读不出来（真正损坏的那格，或结构异常的个别 cell）不该让整表
			// 失败——6.6GB 的库里 27 万条 C2C 只有几十条落在坏页上。
			s.skipped++
			continue
		}
		if err := cb(int64(rowid), payload); err != nil {
			return err
		}
	}
	return nil
}

// Skipped 返回遍历过程中被跳过的 cell 数（坏页/坏指针/坏 payload）。
// 导出结束时可用它提示"有 N 条消息因源库损坏未能读取"。
func (s *StreamDB) Skipped() int { return s.skipped }

func (s *StreamDB) walkInterior(content []byte, hdr int, q *[]uint32, cb func(int64, []byte) error) error {
	nCells := int(binary.BigEndian.Uint16(content[hdr+3 : hdr+5]))
	// 页头 12 字节（interior 比 leaf 多 4 字节的最右子页指针），
	// 之后是 nCells 个 2 字节 cell 指针。边界要带上 hdr——page 1 的 hdr=100。
	if hdr+12+2*nCells > len(content) {
		return nil
	}
	rightPtr := binary.BigEndian.Uint32(content[hdr+8 : hdr+12])
	cellPtrs := content[hdr+12 : hdr+12+2*nCells]
	for i := 0; i < nCells; i++ {
		ptr := int(binary.BigEndian.Uint16(cellPtrs[2*i : 2*i+2]))
		if ptr < hdr || ptr+4 > len(content) {
			continue
		}
		if child := binary.BigEndian.Uint32(content[ptr : ptr+4]); s.validPage(child) {
			*q = append(*q, child)
		}
	}
	if rightPtr != 0 && s.validPage(rightPtr) {
		*q = append(*q, rightPtr)
	}
	return nil
}

// validPage 挡住越界页号。b-tree 指针被读坏时会得到天文数字（如 2.1e9），
// 若直接拿去解密只会得到"页不足 4096 字节"的误导性报错，不如就地丢弃。
// 页数未知（0）时不设限，交给底层 IO 判断。
func (s *StreamDB) validPage(pgno uint32) bool {
	return pgno != 0 && (s.pages == 0 || pgno <= s.pages)
}

// localPayload 取出一条 record 的完整 payload，处理 overflow 链。
//
// SQLite 对 table b-tree 的 leaf cell 用 minLocal=(U-12)*32/255-23 计算本地
// 存放量；index b-tree 用的是 64/255 系数。nt_msg.db 的 master 表行（建表
// SQL 文本）就可能超过本地容量，必须走 overflow 链才能完整取回。
func (s *StreamDB) localPayload(cellBody []byte, plen int) ([]byte, error) {
	U := s.usable
	maxLocal := U - 35
	minLocal := (U-12)*32/255 - 23
	if plen <= maxLocal {
		if len(cellBody) < plen {
			return nil, fmt.Errorf("db: payload %d 超出 cell %d", plen, len(cellBody))
		}
		return cellBody[:plen], nil
	}
	// SQLite 的规则：先按 mod 算出建议的本地长度，若它超过 maxLocal，
	// 则退回 minLocal —— 保证本地部分一定放得下（还要留 4 字节存首页号）。
	local := minLocal + (plen-minLocal)%(U-4)
	if local > maxLocal {
		local = minLocal
	}
	if len(cellBody) < local+4 {
		return nil, fmt.Errorf("db: overflow 头越界（需要 %d，cell 只有 %d）", local+4, len(cellBody))
	}
	overflowStart := binary.BigEndian.Uint32(cellBody[local : local+4])
	out := make([]byte, 0, plen)
	out = append(out, cellBody[:local]...)
	remaining := plen - local
	next := overflowStart
	for remaining > 0 && next != 0 {
		page, err := s.dec.DecryptPage(next)
		if err != nil {
			// 坏页或越界页号都只影响这一条超大字段，已拿到的部分照样返回，
			// 不要让单条消息毁掉整张表的遍历。
			if errors.Is(err, cipher.ErrCorruptPage) || errors.Is(err, cipher.ErrPageOutOfRange) {
				break
			}
			return nil, err
		}
		if len(page) < 4 {
			break
		}
		nextNext := binary.BigEndian.Uint32(page[:4])
		data := page[4:]
		take := U - 4
		if remaining < take {
			take = remaining
		}
		if len(data) < take {
			take = len(data)
		}
		out = append(out, data[:take]...)
		remaining -= take
		next = nextNext
	}
	return out, nil
}

// ---- record 与 master 解析 ----

func parseRecord(payload []byte) ([]any, error) {
	hdrLen, n, err := readVarint(payload, 0)
	if err != nil {
		return nil, err
	}
	// hdrLen 是 SQLite record header 的总字节数（含自身这个 varint），
	// 因此 body 从 record 起点的第 hdrLen 字节开始。
	hdrEnd := int(hdrLen)
	if hdrEnd > len(payload) {
		return nil, fmt.Errorf("db: record header 越界")
	}
	header := payload[n:hdrEnd]
	body := payload[hdrEnd:]
	var cols []any
	bodyOff := 0
	for p := 0; p < len(header); {
		st, sn, err := readVarint(header, p)
		if err != nil {
			return nil, err
		}
		p += sn
		val, sz, err := readSerial(int64(st), body[bodyOff:])
		if err != nil {
			return nil, err
		}
		cols = append(cols, val)
		bodyOff += sz
	}
	return cols, nil
}

func readSerial(t int64, b []byte) (any, int, error) {
	switch {
	case t == 0:
		return nil, 0, nil
	case t == 1:
		return int64(int8(b[0])), 1, nil
	case t == 2:
		return int64(int16(binary.BigEndian.Uint16(b))), 2, nil
	case t == 3:
		return int64(int32(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]))), 3, nil
	case t == 4:
		return int64(int32(binary.BigEndian.Uint32(b))), 4, nil
	case t == 5:
		return int64(uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
			uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])), 6, nil
	case t == 6:
		return int64(binary.BigEndian.Uint64(b)), 8, nil
	case t == 7:
		return float64(binary.BigEndian.Uint64(b)), 8, nil
	case t == 8:
		return int64(0), 0, nil
	case t == 9:
		return int64(1), 0, nil
	case t >= 12 && t%2 == 0: // BLOB
		ln := int(t-12) / 2
		if ln > len(b) {
			return nil, 0, fmt.Errorf("db: blob 长度 %d 越界", ln)
		}
		return append([]byte(nil), b[:ln]...), ln, nil
	case t >= 13 && t%2 == 1: // TEXT
		ln := int(t-13) / 2
		if ln > len(b) {
			return nil, 0, fmt.Errorf("db: text 长度 %d 越界", ln)
		}
		return string(b[:ln]), ln, nil
	}
	return nil, 0, fmt.Errorf("db: 未知 serial type %d", t)
}

// mapColumns 把按"建表列顺序"排好的 record 值，重排成 readOrder 顺序的切片，
// 缺失的列填 nil——与 fill 的读取顺序严格对齐。
func mapColumns(cols []string, rec []any) []any {
	idx := make(map[string]int, len(cols))
	for i, c := range cols {
		idx[c] = i
	}
	out := make([]any, len(readOrder))
	for i, want := range readOrder {
		if j, ok := idx[want]; ok && j < len(rec) {
			out[i] = rec[j]
		}
	}
	return out
}

func matchFilter(m model.Message, f Filter) bool {
	if f.PeerUIN != 0 && m.PeerUIN != f.PeerUIN {
		return false
	}
	if f.SessionID != 0 && m.SessionID != f.SessionID {
		return false
	}
	if f.Since > 0 && m.Timestamp < f.Since {
		return false
	}
	if f.Until > 0 && m.Timestamp > f.Until {
		return false
	}
	return true
}

type masterRow struct {
	typ      string
	name     string
	tblName  string
	rootpage int64
	sql      string
}

func parseMasterRow(payload []byte) (masterRow, error) {
	cols, err := parseRecord(payload)
	if err != nil {
		return masterRow{}, err
	}
	r := masterRow{}
	if len(cols) >= 5 {
		if s, ok := cols[0].(string); ok {
			r.typ = s
		}
		if s, ok := cols[1].(string); ok {
			r.name = s
		}
		if s, ok := cols[2].(string); ok {
			r.tblName = s
		}
		if n, ok := cols[3].(int64); ok {
			r.rootpage = n
		}
		if s, ok := cols[4].(string); ok {
			r.sql = s
		}
	}
	return r, nil
}

// parseColumnNames 从 CREATE TABLE 语句里提取列名顺序。
// QQ 的消息表列名都是协议字段编号（如 40001），无复杂约束，按顶层逗号分割即可。
func parseColumnNames(sql string) []string {
	open := strings.Index(sql, "(")
	if open < 0 {
		return nil
	}
	depth := 0
	end := -1
	for i := open; i < len(sql); i++ {
		switch sql[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil
	}
	inner := sql[open+1 : end]
	parts := strings.Split(inner, ",")
	var cols []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		up := strings.ToUpper(p)
		if strings.HasPrefix(up, "PRIMARY") || strings.HasPrefix(up, "UNIQUE") ||
			strings.HasPrefix(up, "CHECK") || strings.HasPrefix(up, "FOREIGN") ||
			strings.HasPrefix(up, "CONSTRAINT") {
			continue
		}
		f := strings.Fields(p)
		if len(f) == 0 {
			continue
		}
		name := strings.Trim(f[0], "\"`[]")
		if _, err := strconv.Atoi(name); err == nil || isIdent(name) {
			cols = append(cols, name)
		}
	}
	return cols
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// readVarint 读取 SQLite 变长整数（1–9 字节）。
func readVarint(b []byte, off int) (uint64, int, error) {
	var v uint64
	for i := 0; i < 9; i++ {
		if off+i >= len(b) {
			return 0, 0, fmt.Errorf("db: varint 越界")
		}
		c := b[off+i]
		if i == 8 {
			v = (v << 8) | uint64(c)
		} else {
			v = (v << 7) | uint64(c&0x7f)
		}
		if i < 8 && c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return v, 9, nil
}

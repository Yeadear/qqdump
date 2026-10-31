package db

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/Yeadear/qqdump/account"
)

// TestZZDumpRows 打印整表所有行的原始字段，用于核对"被过滤的行"到底是什么。
// QQDUMP_DB=... QQDUMP_UID=... go test ./db -run ZZDumpRows -v
func TestZZDumpRows(t *testing.T) {
	src := os.Getenv("QQDUMP_DB")
	if src == "" {
		t.Skip("no db")
	}
	uid := os.Getenv("QQDUMP_UID")
	if uid == "" {
		t.Fatal("需要 QQDUMP_UID")
	}
	head, err := account.ParseHead(src)
	if err != nil {
		t.Fatal(err)
	}
	key := account.DeriveKey(uid, head.Rand)
	s, err := OpenEncryptedStream(src, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tb := range s.Tables() {
		n, skipped, ph := 0, 0, 0
		var samples []string
		werr := s.walkTable(s.tables[tb].rootpage, func(_ int64, payload []byte) error {
			n++
			cols, e := parseRecord(payload)
			if e != nil {
				return nil
			}
			v := mapColumns(s.tables[tb].cols, cols)
			m := fill(v, s.tables[tb].chatType)
			if m.IsPlaceholder() {
				ph++
				if len(samples) < 6 {
					b, _ := json.Marshal(map[string]any{
						"rowid": 0, "ts": m.Timestamp, "peer": m.PeerUIN,
						"sender": m.SenderUIN, "type": m.MsgType, "segs": len(m.Segments),
					})
					samples = append(samples, string(b))
				}
			}
			return nil
		})
		_ = skipped
		if werr != nil {
			fmt.Println("walk err", werr)
		}
		fmt.Printf("表 %s: 共 %d 行, 占位 %d\n", tb, n, ph)
		for _, s := range samples {
			fmt.Println("  ", s)
		}
	}
}

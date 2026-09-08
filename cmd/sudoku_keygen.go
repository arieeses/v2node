package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
	"github.com/spf13/cobra"
)

var (
	sudokuKeygenMaster string
	sudokuKeygenUsers  int
)

// sudokuUser is one provisioned user: the split private key goes into the
// client config; the user hash is what the node maps to the uuid.
type sudokuUser struct {
	SplitKey string `json:"split_key"`
	UserHash string `json:"user_hash"`
}

type sudokuKeygenOutput struct {
	MasterPublic  string       `json:"master_public"`
	MasterPrivate string       `json:"master_private,omitempty"`
	Users         []sudokuUser `json:"users,omitempty"`
}

// userHashFromSplit reproduces exactly what a sudoku client sends as its
// UserHash: hex(sha256(hex_decode(splitKeyHex))[:8]).
func userHashFromSplit(splitKeyHex string) (string, error) {
	b, err := hex.DecodeString(splitKeyHex)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8]), nil
}

var sudokuKeygenCmd = &cobra.Command{
	Use:   "sudoku-keygen",
	Short: "Generate a sudoku master keypair and per-user split keys + user hashes",
	Long: "Generate the key material for a sudoku node.\n\n" +
		"  v2node sudoku-keygen                         # new master keypair (public + private)\n" +
		"  v2node sudoku-keygen --master <priv> -n 5    # 5 split keys + user hashes for an existing master\n" +
		"  v2node sudoku-keygen -n 5                     # new master + 5 users in one shot\n\n" +
		"Node config gets master_public. Each client gets its split_key; the node's " +
		"user list gets the matching user_hash. Output is JSON.",
	Run: func(_ *cobra.Command, _ []string) {
		out := sudokuKeygenOutput{}

		var masterPriv *crypto.KeyPair
		if sudokuKeygenMaster != "" {
			// Recover the public key from the provided master private scalar/split.
			pub, err := crypto.RecoverPublicKey(sudokuKeygenMaster)
			if err != nil {
				fmt.Println("error: invalid --master:", err)
				return
			}
			out.MasterPublic = crypto.EncodePoint(pub)
		} else {
			pair, err := crypto.GenerateMasterKey()
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			masterPriv = pair
			out.MasterPublic = crypto.EncodePoint(pair.Public)
			out.MasterPrivate = crypto.EncodeScalar(pair.Private)
		}

		for i := 0; i < sudokuKeygenUsers; i++ {
			var split string
			var err error
			if masterPriv != nil {
				split, err = crypto.SplitPrivateKey(masterPriv.Private)
			} else {
				// Split from the provided master private scalar.
				scalar, perr := crypto.ParsePrivateScalar(sudokuKeygenMaster)
				if perr != nil {
					fmt.Println("error: cannot split from --master:", perr)
					return
				}
				split, err = crypto.SplitPrivateKey(scalar)
			}
			if err != nil {
				fmt.Println("error: split:", err)
				return
			}
			uh, err := userHashFromSplit(split)
			if err != nil {
				fmt.Println("error: user hash:", err)
				return
			}
			out.Users = append(out.Users, sudokuUser{SplitKey: split, UserHash: uh})
		}

		j, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(j))
	},
}

func init() {
	sudokuKeygenCmd.Flags().StringVar(&sudokuKeygenMaster, "master", "", "existing master private key (scalar hex); omit to generate a new master")
	sudokuKeygenCmd.Flags().IntVarP(&sudokuKeygenUsers, "users", "n", 0, "also generate N per-user split keys + user hashes")
	command.AddCommand(sudokuKeygenCmd)
}

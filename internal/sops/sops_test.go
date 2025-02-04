package sops

import (
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/assert"
)

func TestValidSopsFiles(t *testing.T) {
	testDir := "testdata"

	expectedResults := []File{
		{Path: "testdata/valid_sops_files/encrypted.env", Metadata: sops.Metadata{}},
		{Path: "testdata/valid_sops_files/encrypted.ini", Metadata: sops.Metadata{}},
		{Path: "testdata/valid_sops_files/encrypted.yaml", Metadata: sops.Metadata{}},
		{Path: "testdata/valid_sops_files/encrypted.yml", Metadata: sops.Metadata{}},
		{Path: "testdata/valid_sops_files/encrypted.json", Metadata: sops.Metadata{}},
	}

	// Loop through files in the testdata directory.
	files, err := FindFiles(testDir)
	assert.NoError(t, err)

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	sort.Slice(expectedResults, func(i, j int) bool {
		return expectedResults[i].Path < expectedResults[j].Path
	})

	for i, file := range expectedResults {
		assert.Equal(t, file.Path, files[i].Path)
	}
}

func TestInvalidSopsFiles(t *testing.T) {
	testDir := "testdata/invalid_sops_files"

	// Loop through files in the testdata directory.
	files, err := FindFiles(testDir)
	assert.NoError(t, err)
	assert.Empty(t, files)
}

func TestGetKeys(t *testing.T) {
	dummyArn := "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	dummyRole := "dummy-role"
	dummyEncryptionContext := map[string]*string{"foo": aws.String("bar")}

	ageKey, err := age.MasterKeyFromRecipient("age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun")
	kmsKey := kms.NewMasterKey(dummyArn, "", nil)
	kmsKeyWithRoleAndContext := kms.NewMasterKey(dummyArn, dummyRole, dummyEncryptionContext)
	assert.NoError(t, err)

	tests := []struct {
		name      string
		sopsfiles File
		expected  []string
	}{
		{
			name:      "Empty Metadata",
			sopsfiles: File{Path: "", Metadata: sops.Metadata{}},
			expected:  []string{},
		},
		{
			name: "Single Key",
			sopsfiles: File{Path: "single/key", Metadata: sops.Metadata{
				KeyGroups: []sops.KeyGroup{
					[]keys.MasterKey{ageKey},
				},
			}},
			expected: []string{"age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"},
		},
		{
			name: "Multiple Keys",
			sopsfiles: File{Path: "Multiple/keys", Metadata: sops.Metadata{
				KeyGroups: []sops.KeyGroup{
					[]keys.MasterKey{ageKey, kmsKey, kmsKeyWithRoleAndContext},
				},
			}},
			expected: []string{
				"age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun",
				"arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
				"arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab+dummy-role|foo:bar",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sopsfiles.ExtractKeys()

			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

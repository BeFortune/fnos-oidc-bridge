package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// 备份文件是自描述的 JSON envelope:KDF 参数随文件走,口令 6-20 位,不落盘。
// Argon2id 派生 32 字节密钥后用 AES-256-GCM 加密完整配置(含 secret)。

const (
	backupMagic   = "fnos-oidc-bridge-backup"
	backupVersion = 1

	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB,NAS 和 PC 都无压力
	argonThreads = 2
	argonKeyLen  = 32
)

var errBackupPassword = errors.New("加密密码须为 6-20 位")

type backupEnvelope struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
	KDF     struct {
		Name    string `json:"name"`
		Salt    string `json:"salt"`
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory"`
		Threads uint8  `json:"threads"`
		KeyLen  uint32 `json:"key_len"`
	} `json:"kdf"`
	Cipher struct {
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
	} `json:"cipher"`
	Data string `json:"data"`
}

func validateBackupPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < 6 || n > 20 {
		return errBackupPassword
	}
	return nil
}

func encryptConfig(cfg *Config, password string) ([]byte, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("序列化配置失败: %w", err)
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	var env backupEnvelope
	env.Magic = backupMagic
	env.Version = backupVersion
	env.KDF.Name = "argon2id"
	env.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
	env.KDF.Time = argonTime
	env.KDF.Memory = argonMemory
	env.KDF.Threads = argonThreads
	env.KDF.KeyLen = argonKeyLen
	env.Cipher.Name = "aes-256-gcm"
	env.Cipher.Nonce = base64.StdEncoding.EncodeToString(nonce)
	env.Data = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil))
	return json.MarshalIndent(env, "", "  ")
}

func decryptConfig(blob []byte, password string) (*Config, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}
	var env backupEnvelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, errors.New("备份文件不是有效的 JSON")
	}
	if env.Magic != backupMagic || env.Version != backupVersion {
		return nil, errors.New("备份文件格式或版本不受支持")
	}
	if env.KDF.Name != "argon2id" || env.Cipher.Name != "aes-256-gcm" {
		return nil, errors.New("备份文件使用了不支持的算法")
	}
	salt, err := base64.StdEncoding.DecodeString(env.KDF.Salt)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("备份文件 KDF 参数损坏")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Cipher.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, errors.New("备份文件 nonce 损坏")
	}
	data, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, errors.New("备份文件密文损坏")
	}
	key := argon2.IDKey([]byte(password), salt, env.KDF.Time, env.KDF.Memory, env.KDF.Threads, env.KDF.KeyLen)
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("解密失败:密码错误或文件已损坏")
	}
	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, errors.New("备份内容不是有效配置")
	}
	cfg.normalize()
	return &cfg, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

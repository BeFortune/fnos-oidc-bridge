package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "配置文件路径")
	dataDir := flag.String("data-dir", "", "数据目录(覆盖配置里的 data_dir)")
	listenOverride := flag.String("listen", "", "公共 OIDC 监听地址(覆盖配置里的 listen)")
	adminSocket := flag.String("admin-socket", "", "fnOS 管理网关 Unix Socket 路径")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *listenOverride != "" {
		cfg.Listen = *listenOverride
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}

	_, refresh, code, session := cfg.TTLs()
	store, err := NewStore(cfg.DataDir, code, session, refresh, cfg.SigningAlg)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	key, kid := store.SigningKey()

	srv := &Server{
		cfg:        cfg,
		configPath: *configPath,
		store:      store,
		fnos:       NewFnOSClient(cfg.FnOS),
		key:        key,
		kid:        kid,
	}

	publicLn, err := listen(cfg.Listen)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", cfg.Listen, err)
	}
	defer publicLn.Close()

	publicServer := &http.Server{Handler: srv.publicRoutes(), ReadHeaderTimeout: 10 * time.Second}
	servers := []*http.Server{publicServer}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("OIDC 服务启动: listen=%s issuer=%s clients=%d", cfg.Listen, cfg.BaseURL, len(cfg.Clients))
		errCh <- serveHTTP(publicServer, publicLn)
	}()

	if *adminSocket != "" {
		adminLn, err := listen("unix:" + *adminSocket)
		if err != nil {
			log.Fatalf("监听管理 Socket %s 失败: %v", *adminSocket, err)
		}
		defer adminLn.Close()
		adminServer := &http.Server{Handler: srv.adminRoutes(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, adminServer)
		go func() {
			log.Printf("fnOS 管理页面启动: socket=%s prefix=%s", *adminSocket, cfg.GatewayPrefix)
			errCh <- serveHTTP(adminServer, adminLn)
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		log.Printf("收到退出信号,关闭服务")
	case err := <-errCh:
		if err != nil {
			log.Printf("服务异常退出: %v", err)
		}
	}
	for _, hs := range servers {
		_ = hs.Close()
	}
}

func serveHTTP(server *http.Server, ln net.Listener) error {
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func listen(addr string) (net.Listener, error) {
	if sock, ok := strings.CutPrefix(addr, "unix:"); ok {
		if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("清理旧 Socket: %w", err)
		}
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(sock, 0o660); err != nil {
			ln.Close()
			return nil, fmt.Errorf("chmod socket: %w", err)
		}
		return ln, nil
	}
	return net.Listen("tcp", addr)
}

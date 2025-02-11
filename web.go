package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/kataras/iris/v12"
)

type webApp struct {
	mu    sync.Mutex
	rules *Rules
	xdp   *xdp

	lastRuleFixed   bool
	lastRuleDisplay bool
}

func runWebApp(ctx context.Context, flags *Flags, rules *Rules, xdp *xdp) error {
	var w webApp
	w.rules = rules
	w.xdp = xdp

	app := iris.New()

	go func() {
		<-ctx.Done()

		// shutdown the running web server
		app.Shutdown(context.TODO())
	}()

	app.HandleDir("/", "./public", iris.DirOptions{
		Gzip:      true,
		IndexName: "index.html",
	})

	v1 := app.Party("/xdp-acl")

	v1.Use(iris.Gzip)

	v1.Get("/IPv4/rules", w.getRules)

	v1.Get("/IPv4/rules/hitcount", w.getHitCount)

	v1.Post("/IPv4/rule", w.addRule)

	v1.Delete("/IPv4/rule", w.delRule)

	// debug assist
	v1.Get("/IPv4/bpfmap/{name:string}", w.notImplement)

	addr := fmt.Sprintf("%s:%d", flags.Server, flags.Port)
	zlog.Infof("Start web server listening on http://%s", addr)

	if err := app.Run(iris.Addr(addr), iris.WithConfiguration(iris.Configuration{
		DisableAutoFireStatusCode: true,
	})); err != nil {
		if errors.Is(err, iris.ErrServerClosed) {
			zlog.Info("Web server is closed")
			return nil
		} else {
			return fmt.Errorf("failed to run web server: %w", err)
		}
	}

	return nil
}

func (w *webApp) getRules(ctx iris.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()

	rules := w.rules.GetRulesWithRealPriority()

	if w.lastRuleFixed && !w.lastRuleDisplay {
		ctx.JSON(rules[:len(rules)-1])
		return
	}

	ctx.JSON(rules)
}

func (w *webApp) getHitCount(ctx iris.Context) {
	type ruleAction struct {
		Priority uint32 `json:"priority"`
		Action   uint32 `json:"action,omitempty"`
		HitCount string `json:"hit_count"`
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	hits, err := retrieveHitCount(w.xdp.updatableObjs.RuleActionV4, len(w.rules.rules))
	if err != nil {
		zlog.Errorf("Failed to retrieve hit count: %v", err)
		ctx.StatusCode(iris.StatusInternalServerError)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	counts := make([]ruleAction, 0, len(hits))
	for priority := uint32(0); priority < uint32(len(hits)); priority++ {
		counts = append(counts, ruleAction{
			Priority: w.rules.GetRealPriority(uint32(priority)),
			HitCount: fmt.Sprintf("%d", hits[priority]),
		})
	}

	ctx.JSON(counts)
}

func (w *webApp) addRule(ctx iris.Context) {
	var rule Rule
	if err := ctx.ReadJSON(&rule); err != nil {
		zlog.Errorf("Failed to add rule: %v", err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	if rule.IsFixed(w.lastRuleFixed) {
		zlog.Errorf("Last rule is fixed to add")

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, "Last rule is fixed to add")
	}

	rule.CreateTime = time.Now().UnixNano() / int64(time.Millisecond)

	w.mu.Lock()
	defer w.mu.Unlock()

	hitcount, err := getHitCount(w.xdp.updatableObjs.RuleActionV4, w.rules)
	if err != nil {
		zlog.Errorf("Failed to delete rule: %v", err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	w.rules.AddRule(&rule)

	if w.reloadXDP(ctx, hitcount) {
		retRule := rule
		retRule.Priority = w.rules.GetRealPriority(rule.Priority)
		ctx.StatusCode(iris.StatusCreated)
		ctx.JSON(&retRule)
	}

	if err := w.rules.Save(); err != nil {
		zlog.Errorf("Failed to save rules: %v", err)
	}
}

func (w *webApp) delRule(ctx iris.Context) {
	priority, err := strconv.Atoi(ctx.Request().URL.Query().Get("priority"))
	if err != nil {
		err := fmt.Errorf("failed to get priority from URL: %w", err)
		zlog.Error(err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	var rule Rule
	rule.Priority = uint32(priority)

	if rule.IsFixed(w.lastRuleFixed) {
		err := fmt.Errorf("last rule priority is fixed to delete")
		zlog.Error(err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	hitcount, err := getHitCount(w.xdp.updatableObjs.RuleActionV4, w.rules)
	if err != nil {
		zlog.Errorf("Failed to delete rule: %v", err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1002, err.Error())
		return
	}

	w.rules.DeleteRule(&rule)

	if w.reloadXDP(ctx, hitcount) {
		ctx.JSON(iris.Map{
			"priority": rule.Priority,
		})
	}

	if err := w.rules.Save(); err != nil {
		zlog.Errorf("Failed to save rules: %v", err)
	}
}

func (w *webApp) reloadXDP(ctx iris.Context, prevHitcount map[uint32]uint64) bool {
	if err := w.xdp.reload(w.rules, prevHitcount); err != nil {
		err = fmt.Errorf("failed to reload XDP: %v", err)
		zlog.Error(err)

		ctx.StatusCode(iris.StatusBadRequest)
		w.outputError(ctx, 1001, err.Error())
		return false
	}

	return true
}

func (w *webApp) notImplement(ctx iris.Context) {
	w.outputError(ctx, 1002, "Not implemented")
}

func (w *webApp) outputError(ctx iris.Context, code int, msg string) {
	ctx.JSON(iris.Map{
		"errCode": code,
		"msg":     msg,
	})
}

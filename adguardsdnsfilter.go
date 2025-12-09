package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/samber/lo"
)

var AdGuardSDNSFilters = []string{
	"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
	"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/CyrillicFilters/common-sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/CyrillicFilters/RussianFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/CyrillicFilters/Belarusian/sections/filter.txt",
	"https://adguardteam.github.io/AdguardFilters/CyrillicFilters/Kazakh/sections/filter.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
}

func adguard(ctx context.Context, c *http.Client) (hasReg *Ruleset, noReg *Ruleset, err error) {
	b, err := getFilter(ctx, c, AdGuardSDNSFilters)
	if err != nil {
		return nil, nil, fmt.Errorf("adguard: %w", err)
	}
	domain := map[string]struct{}{}
	domainRegex := map[string]struct{}{}
	domainSuffix := map[string]struct{}{}

	s := filterlist.NewRuleScanner(bytes.NewReader(b), 1, true)

	for s.Scan() {
		r, _ := s.Rule()
		hr, ok := r.(*rules.NetworkRule)
		if !ok || !hr.IsHostLevelNetworkRule() || hr.Whitelist {
			continue
		}
		if hr.IsRegexRule() {
			continue
		}

		rule := strings.TrimSuffix(strings.TrimLeft(hr.RuleText, "|"), "^")

		if rule == hr.Shortcut {
			rule = strings.TrimPrefix(rule, "://")
			if strings.HasPrefix(rule, ".") {
				domainSuffix[rule] = struct{}{}
				continue
			}
			if strings.HasSuffix(rule, ".") {
				domainRegex[`^(.*\.)?`+rule] = struct{}{}
				continue
			}
			domain[rule] = struct{}{}
			continue
		}
		ruleR := strings.TrimPrefix(rule, "://")
		ruleR = strings.ReplaceAll(ruleR, ".", `\.`)
		reg := strings.ReplaceAll(ruleR, "*", ".*")
		if !strings.HasPrefix(hr.RuleText, "*") {
			reg = `^(.*\.)?` + reg
		}
		if strings.HasSuffix(hr.RuleText, "^") {
			reg = reg + "$"
		}
		domainRegex[reg] = struct{}{}
	}
	for k := range domain {
		domainSuffix["."+k] = struct{}{}
	}

	// 从 rules 中移除指定需要保留的域及其子域（例如 bytebrew.io, gameanalytics.com）
	exclude := []string{"bytebrew.io", "gameanalytics.com"}
	for _, ex := range exclude {
		// 删除精确域名或以 .<ex> 结尾的子域
		for d := range domain {
			if d == ex || strings.HasSuffix(d, "."+ex) {
				delete(domain, d)
			}
		}

		// 删除 domain_suffix 中匹配的项（以 . 开头）
		for s := range domainSuffix {
			if s == "."+ex || strings.HasSuffix(s, "."+ex) {
				delete(domainSuffix, s)
			}
		}

		// 删除 domain_regex 中包含该域名的正则（匹配字面或已转义的形式）
		esc := strings.ReplaceAll(ex, ".", `\.`)
		for r := range domainRegex {
			if strings.Contains(r, ex) || strings.Contains(r, esc) {
				delete(domainRegex, r)
			}
		}
	}

	rules := []map[string][]any{
		{
			"domain":        toAny(domain),
			"domain_suffix": toAny(domainSuffix),
			"domain_regex":  toAny(domainRegex),
		},
	}
	noRegRules := maps.Clone(rules[0])
	delete(noRegRules, "domain_regex")

	return NewRuleSet(rules), NewRuleSet([]map[string][]any{noRegRules}), nil
}

func toAny(m map[string]struct{}) []any {
	sl := lo.Keys(m)
	slices.Sort(sl)
	return lo.Map[string, any](sl, func(item string, index int) any { return item })
}

func getFilter(ctx context.Context, c *http.Client, urls []string) ([]byte, error) {
	// 下载多个 URL，并按顺序原样拼接为一个 byte slice 返回（不做跨 URL 去重）
	var buf bytes.Buffer

	for i, u := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, fmt.Errorf("getFilter: %w", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("getFilter: %w", err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("getFilter: %w", err)
		}

		// 如果不是第一个文件且前一个内容没有以换行结束，插入换行以保证文件之间分隔
		if i > 0 {
			if buf.Len() > 0 {
				last := buf.Bytes()
				if len(last) > 0 && last[len(last)-1] != '\n' {
					buf.WriteByte('\n')
				}
			}
		}
		buf.Write(b)
	}

	return buf.Bytes(), nil
}

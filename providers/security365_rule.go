package providers

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

/*
WildcardMatch is a helper function to match a string against a wildcard pattern.
{
	"items": [
		{
			"user_email": "admin@socam.info",
			"allow_path": ["/api/*","/api/v1/*"],
			"allow_method": ["GET","POST"],
		}
	]
}
*/

type Security365Rule struct {
	UserEmail   string   `json:"user_email"`
	AllowPath   []string `json:"allow_path"`
	AllowMethod []string `json:"allow_method"`
}

type Security365RuleMgr struct {
	Items                []Security365Rule `json:"items"`
	NotFoundedUserReturn bool              `json:"not_founded_user_return"`
	lock                 sync.RWMutex
}

var once sync.Once
var instance *Security365RuleMgr

// GetSecurity365RuleMgrInstance  returns the singleton instance of Security365RuleList
func GetSecurity365RuleMgrInstance() *Security365RuleMgr {
	once.Do(func() {
		instance = &Security365RuleMgr{
			NotFoundedUserReturn: true,
		}
	})
	return instance
}

/*
userEmail: admin@socam.info
policies: "path:/api/*,method:GET,path:/api/v1/*,method:POST"

*/
func (s *Security365RuleMgr) AddItem(userId, policies string) error {

	policylist := strings.Split(policies, ",")
	if userId == "" {
		return errors.New("userId is empty")
	}

	rule := s.FindItem(userId)
	if rule != nil {
		s.RemoveItem(userId)
	}
	pathList := []string{}
	methodList := []string{}
	for _, policy := range policylist {
		if strings.HasPrefix(policy, "path:") {
			pathList = append(pathList, strings.TrimPrefix(policy, "path:"))
		} else if strings.HasPrefix(policy, "method:") {
			methodList = append(methodList, strings.TrimPrefix(policy, "method:"))
		}
	}
	insertOK := false
	if len(pathList) > 0 && len(methodList) > 0 {
		insertOK = true
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	rule = &Security365Rule{
		UserEmail:   userId,
		AllowPath:   pathList,
		AllowMethod: methodList,
	}
	if insertOK {
		s.Items = append(s.Items, *rule)
		return nil
	} else {
		return errors.New("path and method are required")
	}

}

func (s *Security365RuleMgr) GetItemCount() int {
	return len(s.Items)
}

func (s *Security365RuleMgr) Clear() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.Items = []Security365Rule{}
}

func (s *Security365RuleMgr) FindItem(userEmail string) *Security365Rule {
	s.lock.RLock()
	defer s.lock.RUnlock()

	for _, item := range s.Items {
		if item.UserEmail == userEmail {
			return &item
		}
	}
	return nil
}

func (s *Security365RuleMgr) RemoveItem(userEmail string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for i, item := range s.Items {
		if item.UserEmail == userEmail {
			s.Items = append(s.Items[:i], s.Items[i+1:]...)
			break
		}
	}
}

func (s *Security365RuleMgr) PassRule(userId, path, method string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if method == "HEAD" {
		return true
	}

	if path == "/" && method == "GET" { // root path is always allowed
		return true
	}

	item := s.FindItem(userId)
	if item == nil {
		return s.NotFoundedUserReturn
	}
	for _, allowPath := range item.AllowPath {
		if MatchSimple(allowPath, path) {
			for _, allowMethod := range item.AllowMethod {
				if MatchSimple(allowMethod, method) {
					return true
				}
			}
		}
	}
	return false
}

// PassRuleWithRawString   Allowed only if two conditions of path and method are matched
func PassRuleWithRawString(policies, path, method string) bool {

	if policies == "" || method == "HEAD" {
		return true
	}
	if path == "/" && method == "GET" { // root path is always allowed
		return true
	}

	policylist := strings.Split(policies, ",")
	pathList := []string{}
	methodList := []string{}
	for _, policy := range policylist {
		if strings.HasPrefix(policy, "path:") {
			pathList = append(pathList, strings.TrimPrefix(policy, "path:"))
		} else if strings.HasPrefix(policy, "method:") {
			methodList = append(methodList, strings.TrimPrefix(policy, "method:"))
		}
	}

	for _, allowPath := range pathList {
		if MatchSimple(allowPath, path) {
			for _, allowMethod := range methodList {
				if MatchSimple(allowMethod, method) {
					return true
				}
			}
		}
	}
	return false
}

func getPathAndMethodFromPolicy(policies string) (pathList, methodList []string) {
	policylist := strings.Split(policies, ",")
	pathList = []string{}
	methodList = []string{}
	for _, policy := range policylist {
		if strings.HasPrefix(policy, "path:") {
			pathList = append(pathList, strings.TrimPrefix(policy, "path:"))
		} else if strings.HasPrefix(policy, "method:") {
			methodList = append(methodList, strings.TrimPrefix(policy, "method:"))
		}
	}
	return pathList, methodList
}

func checkAllow(pathList, methodList []string, path, method string) bool {
	for _, allowPath := range pathList {
		if MatchSimple(allowPath, path) {
			for _, allowMethod := range methodList {
				if MatchSimple(allowMethod, method) {
					return true
				}
			}
		}
	}
	return false
}

func checkDeny(pathList, methodList []string, path, method string, denyMatch *string) bool {
	for _, denyPath := range pathList {
		if MatchSimple(denyPath, path) {
			*denyMatch = fmt.Sprintf("[path denied] policy: %s  , current: %s  ", denyPath, path)
			return true
		}
	}
	for _, denyMethod := range methodList {
		if MatchSimple(denyMethod, method) {
			*denyMatch = fmt.Sprintf("[method denied] policy: %s  , current: %s  ", denyMethod, method)
			return true
		}
	}
	return false
}

func checkRootAccess(path, method string) bool {
	if path == "/" && method == "GET" { // root path is always allowed
		return true
	}
	return false
}

func CheckRule(allowPolicy, denyPolicy, path, method string) (bool, string) {
	if allowPolicy == "" && denyPolicy == "" {
		return true, "policy is empty"
	}
	if checkRootAccess(path, method) { // root path is always allowed
		return true, "root path is always allowed"
	}

	allowPath, allowMethod := getPathAndMethodFromPolicy(allowPolicy)
	denyPath, denyMethod := getPathAndMethodFromPolicy(denyPolicy)

	// msg := fmt.Sprintf("Permission Denied  [AllowPolicy] %s  [DenyPolicy] %s", session.AllowPolicy, session.DenyPolicy)
	if checkAllow(allowPath, allowMethod, path, method) {
		denyDesc := ""
		if checkDeny(denyPath, denyMethod, path, method, &denyDesc) {
			return false, denyDesc
		} else {
			return true, "all rules passed"
		}
	} else {
		msg := fmt.Sprintf("[AllowPolicy] not matched  [AllowPolicy] %s  current path=%s, method=%s", allowPolicy, path, method)
		return false, msg
	}
}

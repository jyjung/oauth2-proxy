package providers

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
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
	Items []Security365Rule `json:"items"`
	lock  sync.RWMutex
}

var once sync.Once
var instance *Security365RuleMgr

// GetSecurity365RuleMgrInstance  returns the singleton instance of Security365RuleList
func GetSecurity365RuleMgrInstance() *Security365RuleMgr {
	once.Do(func() {
		instance = &Security365RuleMgr{}
	})
	return instance
}

/*
userEmail: admin@socam.info
policies: "path:/api/*,method:GET,path:/api/v1/*,method:POST"

*/
func (s *Security365RuleMgr) AddItem(userEmail, policies string) error {

	policylist := strings.Split(policies, ",")
	if userEmail == "" {
		return errors.New("userEmail is empty")
	}

	rule := s.FindItem(userEmail)
	if rule != nil {
		s.RemoveItem(userEmail)
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
		UserEmail:   userEmail,
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

func (s *Security365RuleMgr) PassRule(userEmail, path, method string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	item := s.FindItem(userEmail)
	if item == nil {
		return true
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

func TestInsertItem(t *testing.T) {
	s := GetSecurity365RuleMgrInstance()
	s.AddItem("jj@aa.bb", "path:/api/*,method:GET,path:/api/v1/*,method:POST")
	if s.GetItemCount() != 1 {
		t.Errorf("expected 1, got %d", s.GetItemCount())
	}
	err := s.AddItem("", "path:/api/*,method:GET,path:/api/v1/*,method:POST")
	if err == nil {
		t.Errorf("expected error, got nil : email is empty")
	}

	err = s.AddItem("tt@aa.bb", "path:/api/*")
	if err == nil {
		t.Errorf("expected error, got nil : path and method are required")
	}
	s.Clear()
}
func TestCheckRule(t *testing.T) {
	s := GetSecurity365RuleMgrInstance()
	s.AddItem("jj@aa.bb", "path:/api/*,method:GET,path:/api/v1/*,method:POST")
	if s.GetItemCount() != 1 {
		t.Errorf("expected 1, got %d", s.GetItemCount())
	}

	assert.Equal(t, true, s.PassRule("jj@aa.bb", "/api/v1/abc", "GET"))
	assert.Equal(t, true, s.PassRule("abc@aa.bb", "/api/v1/abc", "GET"))

	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/api/v1/abc", "PATCH"))  // wrong method
	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/admin/console", "GET")) // wrong path
	s.Clear()

}

func TestDuplicateRule(t *testing.T) {
	s := GetSecurity365RuleMgrInstance()
	if s.GetItemCount() != 0 {
		t.Errorf("expected 0, got %d", s.GetItemCount())
	}

	s.AddItem("jj@aa.bb", "path:/ccc/*,method:GET,path:/ddd/v1/*,method:POST")
	assert.Equal(t, true, s.PassRule("jj@aa.bb", "/ccc/console", "GET"))       // pass
	s.AddItem("jj@aa.bb", "path:/api/*,method:GET,path:/api/v1/*,method:POST") // updateItem
	if s.GetItemCount() != 1 {
		t.Errorf("expected 1, got %d", s.GetItemCount())
	}
	assert.Equal(t, true, s.PassRule("jj@aa.bb", "/api/v1/abc", "GET"))
	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/ccc/console", "GET")) // wrong path

}

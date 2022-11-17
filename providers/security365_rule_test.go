package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	assert.Equal(t, true, s.PassRule("abc@aa.bb", "/api/v1/abc", "GET")) //

	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/api/v1/abc", "PATCH"))  // wrong method
	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/admin/console", "GET")) // wrong path
	s.Clear()

}

func TestCheckRuleWithRawString(t *testing.T) {
	policies := "path:/api/*,method:GET,path:/api/v1/*,method:POST"

	assert.Equal(t, true, PassRuleWithRawString(policies, "/api/v1/abc", "GET"))
	assert.Equal(t, true, PassRuleWithRawString(policies, "/api/v1/ddee", "GET")) //

	assert.Equal(t, false, PassRuleWithRawString(policies, "/api/v1/abc", "PATCH"))  // wrong method
	assert.Equal(t, false, PassRuleWithRawString(policies, "/admin/console", "GET")) // wrong path

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
	assert.Equal(t, true, s.PassRule("jj@aa.bb", "/api/v1/abc", "GET"))   // check new rule is updated
	assert.Equal(t, false, s.PassRule("jj@aa.bb", "/ccc/console", "GET")) // check previous rule cleared
	s.Clear()
}

func TestCheckRuleEx(t *testing.T) {
	allowPolicy := "path:/api/*,path:/api/v1/*,method:*"
	denyPolicy := "path:/api/v1/denytest*,method:DELETE"

	ok, _ := CheckRule(allowPolicy, denyPolicy, "/api/v1/abc", "GET")
	assert.Equal(t, true, ok)
	ok, _ = CheckRule(allowPolicy, denyPolicy, "/api/v1/eeeeeeeeeee", "GET")
	assert.Equal(t, true, ok)
	ok, _ = CheckRule(allowPolicy, denyPolicy, "/api/v1/abc", "PATCH")
	assert.Equal(t, true, ok)

	ok, _ = CheckRule(allowPolicy, denyPolicy, "/api/v1/denytest/eerrrr", "GET")
	assert.Equal(t, false, ok) // deny rule with path
	ok, _ = CheckRule(allowPolicy, denyPolicy, "/api/v1/abc", "DELETE")
	assert.Equal(t, false, ok) // deny rule with method
	ok, _ = CheckRule(allowPolicy, denyPolicy, "/admin/console", "GET")
	assert.Equal(t, false, ok) // allow policy wrong path
}

func TestRaceConditions(t *testing.T) {
	s := GetSecurity365RuleMgrInstance()
	// TODO: write race condition test
	s.Clear()
}

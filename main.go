package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	_ "github.com/go-sql-driver/mysql"
)

var enforcer *casbin.Enforcer

func init() {

	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	// You can also use an already existing gorm instance with gormadapter.NewAdapterByDB(gormInstance)
	a, _ := gormadapter.NewAdapter("mysql", "root:a@tcp(127.0.0.1:3306)/") // Your driver and data source.
	log.Printf("%v", a)
	e, _ := casbin.NewEnforcer("config/rbac_model.conf", a)

	enforcer = e

	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/abc", true)

	// Load the policy from DB.
	// e.LoadPolicy()

	// Check the permission.
	ok, err := e.Enforce("alice", "data1", "read")
	if err != nil {
		log.Fatalf("enforce error")
	}

	if ok {
		log.Printf("ok")
	} else {

		log.Printf("no ok")
	}

	enforcer.AddPolicy("added_user", "data1", "read")
	hasPolicy := enforcer.HasPolicy("added_user", "data1", "read")
	fmt.Println(hasPolicy) // true, we added that policy successfully

	// remove a policy, then use HasPolicy() to confirm that
	enforcer.RemovePolicy("alice", "data1", "read")
	hasPolicy = enforcer.HasPolicy("alice", "data1", "read")
	fmt.Println(hasPolicy) // false, we deleted that policy successfully

	// Modify the policy.
	// e.RemovePolicy(...)
	addPolicyIfNo("alice", "data1", "read")
	addPolicyIfNo("admin", "data1", "write")
	addPolicyIfNo("admin", "data2", "read")
	addPolicyIfNo("admin", "data2", "write")
	addPolicyIfNo("bob", "data2", "write")
	// enforcer.AddGroupingPolicy( "amber", "bob")
	// enforcer.AddGroupingPolicy( "amber", "admin")
	// enforcer.AddGroupingPolicy( "abc", "admin")

	// Save the policy back to DB.
	// e.SavePolicy()

	// allSubjects := enforcer.GetAllSubjects()
	// fmt.Println(allSubjects)
	// allSubjects = enforcer.GetAllNamedSubjects("p")
	// fmt.Println(allSubjects)

	// roles, _ := enforcer.GetRolesForUser("admin")
	
	roles,err  := enforcer.GetRolesForUser("amber", )
	fmt.Println(roles)
	users, _ := enforcer.GetUsersForRole("admin")
	fmt.Println(users)

	defer e.SavePolicy()
}

func addPolicyIfNo(params ...interface{}) {
	if !enforcer.HasPolicy(params...) {
		enforcer.AddPolicy(params...)
	}
}

func main() {

	// for _, role := range roles {
	// 	fmt.Println(role)
	// }

}

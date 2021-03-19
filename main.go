package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	_ "github.com/go-sql-driver/mysql"
)

var e *casbin.Enforcer

func init() {
	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	// You can also use an already existing gorm instance with gormadapter.NewAdapterByDB(gormInstance)
	a, _ := gormadapter.NewAdapter("mysql", "root:a@tcp(127.0.0.1:3306)/") // Your driver and data source.
	log.Printf("%v",a)
	e, _ := casbin.NewEnforcer("config/rbac_model.conf", a)

	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/abc", true)

	// Load the policy from DB.
	e.LoadPolicy()

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

	// Modify the policy.
	// if !e.HasPolicy("alice", "data1", "write") {
	// 	e.AddPolicy("alice", "data1", "write")
	// }
	addPolicyIfNo("alice", "data1", "write")
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	// e.SavePolicy()

	defer e.SavePolicy()
}

func addPolicyIfNo(params ...interface{}) {
	fmt.Printf("%v %v %v", params...)

	if !e.HasPolicy(params...) {
		e.AddPolicy("alice", "data1", "write")
	}
	// if !e.HasPolicy("alice", "data1", "write") {
	// 	e.AddPolicy("alice", "data1", "write")
	// }
}

func main() {
}

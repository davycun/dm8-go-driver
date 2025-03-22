/*
 * Copyright (c) 2000-2018, 达梦数据库有限公司.
 * All rights reserved.
 */
package dm

import (
	"net/url"
	"testing"
)

func TestUp(t *testing.T) {

	u, err := url.Parse("dm://user:password@host:2345")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "host:2345" {
		t.Fatalf("host err ")
	}
}

// dm://user:password@host:port[?propName1=propValue1][&propName2=propValue2]…
// dm://user:password@GroupName[?propName1=propValue1][&propName2=propValue2]…
// dm://user:password@GroupName?GroupName=(host1:port1,host2:port2,…)[&propName1=propValue1]…
// dm://user:password@host:port?dialName=anyName[&propName1=propValue1]…

func TestParse(t *testing.T) {

	dsnList := []struct {
		dsn      string
		host     string
		user     string
		password string
		hasErr   bool
		props    map[string]string
	}{
		{
			dsn:      "dm://user:password@host:port?p1=v1&p2=v2",
			hasErr:   true, //port err
			host:     "host:123",
			user:     "user",
			password: "password",
		},
		{
			dsn:      "user:password@host:123?p1=v1&p2=v2",
			hasErr:   true, //schema error
			host:     "host:123",
			user:     "user",
			password: "password",
		},
		{
			dsn:      "dm://:psswd@host:123?p1=v1&p2=v2",
			hasErr:   true, //not allow empty user
			host:     "host:123",
			user:     "user",
			password: "psswd",
		},
		{
			dsn:      "dm://user:psswd@GroupName?p1=v1&p2=v2",
			hasErr:   true, //host err
			host:     "",
			user:     "user",
			password: "psswd",
		},
		{
			dsn:      "dm://user:psswd@GroupName?GroupName=(host1:5236,host2:5236)&p1=v1&p2=v2",
			hasErr:   false, //host err
			host:     "host1:5236,host2:5236",
			user:     "user",
			password: "psswd",
			props:    map[string]string{"p1": "v1", "p2": "v2"},
		},
		{
			dsn:      "dm://user:@host:123?p1=v1&p2=v2",
			hasErr:   false,
			host:     "host:123",
			user:     "user",
			password: "", //allow empty password
		},
		{
			dsn:      "dm://user:pas:@#$%^&()!sw+=-~ord@host:5236?p1=v1&p2=v2",
			hasErr:   false, //allow password contains special char
			host:     "host:5236",
			user:     "user",
			password: "pas:@#$%^&()!sw+=-~ord",
		},
	}

	for i, v := range dsnList {
		props, host, user, password, err := parseDSN2(v.dsn)
		if v.hasErr && err != nil {
			continue
		}
		if v.hasErr && err == nil {
			t.Fatalf("test case %d failed", i)
		}
		if !v.hasErr && v.host != host {
			t.Fatalf("test case %d failed host not equal", i)
		}
		if !v.hasErr && v.user != user {
			t.Fatalf("test case %d failed user not equal", i)
		}
		if !v.hasErr && v.password != password {
			t.Fatalf("test case %d failed password not equal", i)
		}

		if !v.hasErr {
			for k, vs := range v.props {
				if props.GetString(k, "") != vs {
					t.Fatalf("test case %d failed props [%s] not equal", i, k)
				}
			}
		}
	}

}

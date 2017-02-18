package main

import (
	"fmt"
	"os"

	"encoding/json"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"io/ioutil"
	"net/http"
	"time"
	"golang.org/x/crypto/ssh/terminal"
)

var token Token

const (
	USERNAME   = "user"
	PASSWORD   = "password"
	HOST       = "host"
	FILTER     = "filter"
	SIZE       = "size"
	TOKEN_FILE = "token.json"
)

func main() {

	//Load token
	loadToken()
	app := cli.NewApp()
	app.Version = "1.0.0"
	app.Name = "iZettle login cli"
	app.Description = "cli for a login system"
	app.Commands = []cli.Command{
		{
			Name:        "login",
			Aliases:     []string{"li"},
			Category:    "ACL",
			Usage:       "Login",
			UsageText:   "Login",
			Description: "Login with username and password",
			Flags: []cli.Flag{
				cli.StringFlag{Name: HOST, Value: "http://localhost:8080"},
				cli.StringFlag{Name: USERNAME, Value: token.User},
				cli.StringFlag{Name: PASSWORD},
			},
			Action: loginAction,
		}, {
			Name:        "register",
			Aliases:     []string{"re"},
			Category:    "ACL",
			Usage:       "Register",
			UsageText:   "Register",
			Description: "Register with username and password",
			Flags: []cli.Flag{
				cli.StringFlag{Name: HOST, Value: "http://localhost:8080"}, cli.StringFlag{Name: USERNAME, Value: token.User},
				cli.StringFlag{Name: PASSWORD},
			},
			Action: register,
		}, {
			Name:      "logout",
			Aliases:   []string{"lo"},
			Category:  "ACL",
			Usage:     "Logout",
			UsageText: "Logout based on previous login",
			Action:    logout,
		}, {
			Name:      "listevent",
			Aliases:   []string{"le"},
			Category:  "Storage",
			Usage:     "List your events.",
			UsageText: "List all your events, or certain kind of event by suppling a filter.",
			Flags: []cli.Flag{
				cli.StringFlag{Name: FILTER},
				cli.IntFlag{Name: SIZE, Value: 5},
			},
			Action: listEvent,
		},
	}
	app.Run(os.Args)
}

func loginAction(c *cli.Context) {
	password := c.String(PASSWORD)
	token.User = c.String(USERNAME)
	token.Host = c.String(HOST)
	login(token.Host, token.User, password)
}

func login(host, user, password string) {
	if user != "" && password != "" && host != "" {
		tokenBytes, err := acl("login", host, user, password, "")
		if err == nil {
			err := json.Unmarshal(tokenBytes, &token)
			if err != nil {
				fmt.Printf("Failed parse token:\n%s", err)
			} else {
				token.User = user
				token.Host = host
				b, _ := json.Marshal(token)
				err = ioutil.WriteFile(TOKEN_FILE, b, 0644)
				if err == nil {
					fmt.Println("Login successful")
				}
			}
		} else {
			fmt.Println(err.Error())
		}
	} else {
		fmt.Println("Not engouth information provided")
	}
}

func logout(c *cli.Context) {
	if token.Host != "" && (token.User != "" || token.Token != "") {
		resp, err := acl("logout", token.Host, token.User, "", token.Token)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(resp))
		removeToken()
	} else {
		fmt.Println("Can not find previous login information.")
	}
}

func register(c *cli.Context) {
	password := c.String(PASSWORD)
	token.User = c.String(USERNAME)
	token.Host = c.String(HOST)
	if token.User != "" && password != "" && token.Host != "" {
		resp, err := acl("register", token.Host, token.User, password, "")
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(resp))
	} else {
		fmt.Println("Not engouth information provided")
	}

}

func listEvent(c *cli.Context) {
	filter := c.String(FILTER)
	size := c.Int(SIZE)
	refreshToken()
	if token.Token != "" && token.Host != "" && token.User != "" {
		url := fmt.Sprintf("%s/user/%s/event/%s?token=%s&size=%d", token.Host, token.User, filter, token.Token, size)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error in getting events list:%s\n", err.Error())
		} else {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response")
			}
			if len(body) > 0 {
				if resp.StatusCode != 200 {
					fmt.Printf("Error listing evnets:\n%s\n", string(body))
				} else {
					var events []Event
					err := json.Unmarshal(body, &events)
					if err != nil {
						fmt.Printf("Failed parse token %s\n", err)
					} else {
						for _, ev := range events {
							fmt.Printf("Event:%s \tat %s \tdata:%s\n", ev.EventType, time.Unix(0, ev.Date*int64(time.Millisecond)), ev.Data)
						}
					}
				}
			}

		}
	} else {
		fmt.Println("Invalid token token, Try login again")
	}
}

func acl(function string, host string, user string, password string, token string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s?user=%s&password=%s&token=%s", host, function, user, password, token)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error reading response")
		return nil, err
	} else {
		codeSeries := resp.StatusCode / 100
		body, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil || codeSeries > 3 {
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Network error calling %s function:%s\n", function, err.Error()))
			} else {
				return nil, errors.New(fmt.Sprintf("Error calling %s function:%s\n", function, string(body)))
			}
		} else {
			return body, nil
		}
	}
}

func refreshToken() error {
	if token.Token != "" && token.Host != "" && token.User != "" {
		tte := token.ExpireTime*time.Millisecond.Nanoseconds() - time.Now().UnixNano()
		if tte < 0 {
			fmt.Printf("Token expired please type in password for host:%s user:%s\n", token.Host, token.User)
			password, err := terminal.ReadPassword(0)
			if err == nil {
				login(token.Host, token.User, string(password))
				return nil
			} else {
				return errors.Wrap(err, "Error reading input")
			}
		} else if tte <= time.Second.Nanoseconds()*10 {
			fmt.Printf("Token is getting expired %d seconds\n", tte/time.Second.Nanoseconds())
			tokenBytes, err := acl("renewtoken", token.Host, token.User, "", token.Token)
			if err == nil {
				err := json.Unmarshal(tokenBytes, &token)
				if err == nil {
					err = saveToken()
					if err == nil {
						fmt.Println("Token renew successful")
					}
					return err
				} else {
					return errors.Wrap(err, "Failed parse token")
				}
			} else {
				return err
			}
		} else {
			//No need to update token
			return nil
		}
	} else {
		return errors.New("No valid token found")
	}
}
func loadToken() error {
	b, err := ioutil.ReadFile(TOKEN_FILE)
	if err == nil {
		return json.Unmarshal(b, &token)
	} else {
		return err
	}
}

func saveToken() error {
	b, _ := json.Marshal(token)
	return ioutil.WriteFile(TOKEN_FILE, b, 0644)
}

func removeToken() error {
	return os.Remove(TOKEN_FILE)
}

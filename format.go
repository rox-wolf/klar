package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nlopes/slack"
	"github.com/olekukonko/tablewriter"
	"github.com/optiopay/klar/clair"
)

var SeverityStyle = map[string]string{
	"Defcon1":    "\033[1;31m%s\033[0m",
	"Critical":   "\033[1;31m%s\033[0m",
	"High":       "\033[0;31m%s\033[0m",
	"Medium":     "\033[0;33m%s\033[0m",
	"Low":        "\033[0;94m%s\033[0m",
	"Negligible": "\033[0;94m%s\033[0m",
	"Unknown":    "\033[0;97m%s\033[0m",
}

func getSeverityStyle(status string) string {
	if val, ok := SeverityStyle[status]; ok {
		// Return matched style
		return fmt.Sprintf(val, status)
	}

	// Return default style Unknown if not matched
	return fmt.Sprintf(SeverityStyle["Unknown"], status)
}

// Return yellow or red color, depending on high vuln count.
func colorSelector() (color string) {
	if len(store["High"]) > 0 {
		color = "danger"
	} else {
		color = "warning"
	}
	return
}

func standardFormat(conf *config, vs []*clair.Vulnerability) int {
	vsNumber := 0
	iteratePriorities(priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })

	fmt.Printf("\n")

	iteratePriorities(conf.ClairOutput, func(sev string) {
		for _, v := range store[sev] {
			fmt.Printf("%s: [%s] \nFound in: %s [%s]\nFixed By: %s\n%s\n%s\n", v.Name, v.Severity, v.FeatureName,
				v.FeatureVersion, v.FixedBy, v.Description, v.Link)
			fmt.Println("-----------------------------------------")
			if conf.IgnoreUnfixed {
				if v.FixedBy != "" {
					vsNumber++
				}
			} else {
				vsNumber++
			}
		}
	})
	return vsNumber
}

func slackFormat(conf *config, vs []*clair.Vulnerability) int {
	var messg strings.Builder
	vsNumber := 0

	iteratePriorities(conf.ClairOutput, func(sev string) {
		messg.WriteString(fmt.Sprintf("%s: %d\n", sev, len(store[sev])))
		vsNumber += len(store[sev])
	})

	if vsNumber > 0 {

		attachment := slack.Attachment{
			Pretext:  fmt.Sprintf("*Image Name: [%s]*\n_Vulnerabilities found: %d_", conf.DockerConfig.ImageName, vsNumber),
			Color:    colorSelector(),
			Fallback: messg.String(),
			Text:     messg.String(),
			//Footer:     "clair scan",
			//FooterIcon: "https://platform.slack-edge.com/img/default_application_icon.png",
			Ts: json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
		}
		msg := slack.WebhookMessage{
			Attachments: []slack.Attachment{attachment},
		}

		err := slack.PostWebhook(conf.SlackWebhook, &msg)
		if err != nil {
			fmt.Println(err)
		}

	}

	return vsNumber
}

func jsonFormat(conf *config, output jsonOutput) int {
	vsNumber := 0
	iteratePriorities(conf.ClairOutput, func(sev string) {
		if conf.IgnoreUnfixed {
			// need to iterate over store[sev]
			for _, v := range store[sev] {
				if v.FixedBy != "" {
					vsNumber++
				}
			}
		} else {
			vsNumber += len(store[sev])
		}
		output.Vulnerabilities[sev] = store[sev]
	})
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(output)

	return vsNumber
}

func tableFormat(conf *config, vs []*clair.Vulnerability) int {
	vsNumber := 0
	iteratePriorities(priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })
	fmt.Printf("\n")

	table := tablewriter.NewWriter(os.Stdout)
	header := []string{
		"Severity", "Name", "FeatureName", "FeatureVersion", "FixedBy", "Description", "Link",
	}
	table.SetHeader(header)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("-")
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	var data [][]string

	iteratePriorities(conf.ClairOutput, func(sev string) {
		for _, v := range store[sev] {
			data = append(data, []string{
				getSeverityStyle(v.Severity),
				v.Name,
				v.FeatureName,
				v.FeatureVersion,
				v.FixedBy,
				v.Description,
				v.Link,
			})

			if conf.IgnoreUnfixed {
				if v.FixedBy != "" {
					vsNumber++
				}
			} else {
				vsNumber++
			}
		}
	})

	table.AppendBulk(data)

	if len(data) > 0 {
		table.Render()
	}
	return vsNumber
}

func iteratePriorities(output string, f func(sev string)) {
	filtered := true
	for _, sev := range priorities {
		if filtered {
			if sev != output {
				continue
			} else {
				filtered = false
			}
		}

		if len(store[sev]) != 0 {
			f(sev)
		}
	}
}

package jhove

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const ValidStatus = "Well-Formed and valid"

const (
	// warc (mandatory)
	warcRecordIDKey  = "Warc-Record-ID header value."
	contentLengthKey = "Content-Length header value."
	warcDateKey      = "Warc-Date header value."
	warcTypeKey      = "Warc-Type header value."

	// warc
	contentTypeKey        = "Content-Type header value."
	warcConcurrentToKey   = "Warc-Concurrent-To header value."
	warcBlockDigestkey    = "Warc-Block-Digest header value."
	warcBlockDigestAlgKey = "Block-Digest-Algorithm value."
	warcPayloadDigestKey  = "Warc-Payload-Digest header value."
	payloadDigestAlgKey   = "Payload-Digest-Algorithm value."

	warcIpAddressKey  = "Warc-IP-Address header value."
	warcRefersToKey   = "Warc-Refers-To header value."
	warcTargetUriKey  = "Warc-Target-URI header value."
	warcWarcInfoIDKey = "Warc-Warcinfo-ID header value."
	warcFilenameKey   = "WarcFilename header value."

	// parser specific
	offsetKey         = "Record offset in WARC file."
	isNonCompliantKey = "isNonCompliant value."

	// payload
	valueProtocolUserAgentKey = "ProtocolUserAgent header value."
	valueProtocolVersionKey   = "ProtocolVersion header value."
	payLoadDigestAlgorithm    = "Payload-Digest-Algorithm value."
	payloadLengthKey          = "PayloadLength value."
)

type Record struct {
	WarcRecordID      string   `json:"warcRecordId"`
	ContentLength     int64    `json:"contentLength"`
	WarcDate          string   `json:"warcDate"`
	WarcType          string   `string:"warcType"`
	ContentType       string   `json:"ContentType,omitempty"`
	WarcConcurrentTo  []string `json:"warcConcurrentTo,omitempty"`
	WarcBlockDigest   string   `json:"warcBlockDigest,omitempty"`
	WarcPayloadDigest string   `json:"warcPayloadDigest,omitempty"`
	WarcIPAdress      string   `json:"warcIpAddress,omitempty"`
	WarcRefersTo      []string `json:"warcRefersTo,omitempty"`
	WarcTargetUri     string   `json:"warcTargetUri,omitempty"`
	WarcWarcInfoID    string   `json:"warcWarcInfoId,omitempty"`
	WarcFilename      string   `json:"warcFilename,omitempty"`
	FileOffset        int64    `json:"offset"`
}

func (p Record) String() string {
	return fmt.Sprintf(
		"\tOffset: %d\n"+
			"\tWARC-Record-ID: %s\n"+
			"\tContent-Length: %d\n"+
			"\tWARC-Date: %s\n"+
			"\tWARC-Type: %s\n"+
			"\tContent-Type: %s\n"+
			"\tWarc-Target-Uri: %s\n",
		p.FileOffset,
		p.WarcRecordID,
		p.ContentLength,
		p.WarcDate,
		p.WarcType,
		p.ContentType,
		p.WarcTargetUri)
}

type Report struct {
	Date     time.Time `json:"date"`
	Filename string    `json:"filename"`
	Format   string    `json:"format"`
	Version  string    `json:"version"`
	Status   string    `json:"status"`
	Messages []Message `json:"messages"`
	Records  []Record  `json:"records,omitempty"`
}

func (r *Report) String() string {
	s := fmt.Sprintf("Date: %v\n", r.Date)
	s += fmt.Sprintf("Filename: %s\n", r.Filename)
	s += fmt.Sprintf("Format: %s/%s\n", r.Format, r.Version)
	s += fmt.Sprintf("Status: %s\n", r.Status)
	if len(r.Messages) > 0 {
		s += fmt.Sprintln("Messages:")
	}
	for i, msg := range r.Messages {
		s += fmt.Sprintf("  %d. %s\t%-20s %s\n", i+1, msg.Severity, msg.Message, msg.SubMessage)
	}
	if len(r.Records) > 0 {
		s += fmt.Sprintln("Records (noncompliant):")
	}
	for i, p := range r.Records {
		s += fmt.Sprintf("%4d.%v\n", i, p)
	}
	return s
}

type Message struct {
	Message    string `xml:",chardata" json:"message"`
	SubMessage string `xml:"subMessage,attr" json:"subMessage"`
	Severity   string `xml:"severity,attr" json:"severity"`
}

type status struct {
	Value string `xml:",chardata"`
}

type property struct {
	Name   string `xml:"name"`
	Values values `xml:"values"`
}

type values struct {
	Values []value `xml:"value"`
}

type value struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type messages struct {
	Messages []Message `xml:"message"`
}

func ParseReport(path string, verbose bool) (*Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := xml.NewDecoder(file)
	var report Report
	// state is used to bypass top level <property> tag (because streaming xml parsing)
	// and to kee
	state := 0

	for {
		token, err := decoder.Token()
		if token == nil || errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("error decoding token: %w", err)
		}

		switch ty := token.(type) {
		case xml.StartElement:
			if verbose {
				if ty.Name.Local == "property" {
					if state == 6 {
						state++
						continue
					}
					var p property
					if err = decoder.DecodeElement(&p, &ty); err != nil {
						return nil, fmt.Errorf("error decoding record: %w", err)
					}
					// record is kept if non-compliant
					var record Record
					values := make(map[string]string)
					for _, value := range p.Values.Values {
						values[value.Key] = value.Value
					}
					if compliant, ok := values[isNonCompliantKey]; !ok || compliant == "true" {
						continue
					}
					for key, value := range values {
						switch key {
						case offsetKey:
							record.FileOffset, err = strconv.ParseInt(value, 10, 64)
							if err != nil {
								return nil, fmt.Errorf("error parsing record offset: %w", err)
							}
						case warcRecordIDKey:
							record.WarcRecordID = value
						case contentLengthKey:
							record.ContentLength, err = strconv.ParseInt(value, 10, 64)
							if err != nil {
								return nil, fmt.Errorf("error parsing record content length: %w", err)
							}
						case warcDateKey:
							record.WarcDate = value
						case warcTypeKey:
							record.WarcType = value
						case contentTypeKey:
							record.ContentType = value
						case warcConcurrentToKey:
							record.WarcConcurrentTo = append(record.WarcConcurrentTo, value)
						case warcBlockDigestkey:
							if alg, ok := values[warcBlockDigestAlgKey]; ok {
								record.WarcBlockDigest = alg + ":" + value
							} else {
								record.WarcBlockDigest = value
							}
						case warcPayloadDigestKey:
							if alg, ok := values[payloadDigestAlgKey]; ok {
								record.WarcPayloadDigest = alg + ":" + value
							} else {
								record.WarcPayloadDigest = value
							}
						case warcIpAddressKey:
							record.WarcIPAdress = value
						case warcRefersToKey:
							record.WarcRefersTo = append(record.WarcRefersTo, value)
						case warcTargetUriKey:
							record.WarcTargetUri = value
						case warcWarcInfoIDKey:
							record.WarcWarcInfoID = value
						case warcFilenameKey:
							record.WarcFilename = value
						}
					}

					report.Records = append(report.Records, record)
					continue
				}
			} else if state == 6 {
				// there is 6 state increments below, meaning parsing can be
				// stopped because only verbose mode need to parse properties
				return &report, nil
			}

			if ty.Name.Local == "messages" {
				var messages messages
				if err = decoder.DecodeElement(&messages, &ty); err != nil {
					return nil, fmt.Errorf("error decoding Messages: %w", err)
				}

				for _, message := range messages.Messages {
					report.Messages = append(report.Messages, message)
				}
				state++
			} else if ty.Name.Local == "version" {
				var status status
				if err = decoder.DecodeElement(&status, &ty); err != nil {
					return nil, fmt.Errorf("error decoding status: %w", err)
				}
				report.Version = status.Value
				state++
			} else if ty.Name.Local == "format" {
				var format struct {
					Value string `xml:",chardata"`
				}
				if err = decoder.DecodeElement(&format, &ty); err != nil {
					return nil, fmt.Errorf("error decoding status: %w", err)
				}
				report.Format = format.Value
				state++
			} else if ty.Name.Local == "status" {
				var status status
				if err = decoder.DecodeElement(&status, &ty); err != nil {
					return nil, fmt.Errorf("error decoding status: %w", err)
				}
				report.Status = status.Value
				state++
			} else if ty.Name.Local == "date" {
				var date struct {
					Date string `xml:",chardata"`
				}
				if err = decoder.DecodeElement(&date, &ty); err != nil {
					return nil, fmt.Errorf("error decoding date: %w", err)
				}
				report.Date, err = time.Parse(time.RFC3339, date.Date)
				if err != nil {
					return nil, fmt.Errorf("error parsing date using RFC3339: %w", err)
				}
				state++
			} else if ty.Name.Local == "repInfo" {
				for _, attr := range ty.Attr {
					if attr.Name.Local == "uri" {
						report.Filename = attr.Value[strings.LastIndexByte(attr.Value, byte(os.PathSeparator))+1:]
					}
				}
				state++
			}
		}
	}
	return &report, nil
}

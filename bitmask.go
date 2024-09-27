/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

import (
	"fmt"
	"log"
	"strings"
)

type TagMask uint32

const (
	NewName TagMask = 1 << iota
	HighVolume
	BadIP
	CdnTracker
	LikelyMalware
	LikelyBotnetCC
	Foo
	Bar
	Baz
	Gazonk
	Frotz
)

var DefinedTags = []string{"newname", "highvolume", "badip", "cdntracker", "likelymalware", "likelybotnetcc",
	// "childporn",
	"foo", "bar", "baz", "gazonk", "frotz"}

func SetTag(b, tag TagMask) TagMask    { return b | tag }
func ClearTag(b, tag TagMask) TagMask  { return b &^ tag }
func ToggleTag(b, tag TagMask) TagMask { return b ^ tag }
func HasTag(b, tag TagMask) bool       { return b&tag != 0 }

func (tm *TagMask) SetTag(tag TagMask)      { *tm = *tm | tag }
func (tm *TagMask) ClearTag(tag TagMask)    { *tm = *tm &^ tag }
func (tm *TagMask) ToggleTag(tag TagMask)   { *tm = *tm ^ tag }
func (tm *TagMask) HasTag(tag TagMask) bool { return *tm&tag != 0 }

func (tm *TagMask) NumTags() int {
	var res int
	for i := 0; i < 32; i++ {
		if tm.HasTag(TagMask(1 << i)) {
			// fmt.Printf("Bit %d is set\n", i)
			res++
		}
	}
	return res
}

func StringsToTagMask(ss []string) (TagMask, error) {
	var res TagMask
	for _, s := range ss {
		switch strings.ToLower(s) {
		case "newname":
			res.SetTag(NewName)
		case "highvolume":
			res.SetTag(HighVolume)
		case "badip":
			res.SetTag(BadIP)
		case "cdntracker":
			res.SetTag(CdnTracker)
		case "likelymalware":
			res.SetTag(LikelyMalware)
		case "likelybotnetcc":
			res.SetTag(LikelyBotnetCC)
			//		case "childporn":
			//			res.SetTag(ChildPorn)
		case "foo":
			res.SetTag(Foo)
		case "bar":
			res.SetTag(Bar)
		case "baz":
			res.SetTag(Baz)
		case "gazonk":
			res.SetTag(Gazonk)
		case "frotz":
			res.SetTag(Frotz)
		default:
			log.Printf("Error: unknown tag: \"%s\"", s)
			return res, fmt.Errorf("unknown tapir tag: \"%s\"", s)
		}
	}
	return res, nil
}

type Action uint8

const (
	NXDOMAIN Action = 1 << iota
	NODATA
	DROP
	REDIRECT
	WHITELIST
	PASSTHRU
	UnknownAction
)

func (tn *TapirName) HasAction(action Action) bool { return tn.Action&action != 0 }

func StringToAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "whitelist", "passthru":
		return WHITELIST, nil
	case "nxdomain":
		return NXDOMAIN, nil
	case "nodata":
		return NODATA, nil
	case "drop":
		return DROP, nil
	case "redirect":
		return REDIRECT, nil
	default:
		log.Printf("Error: unknown RPZ action: \"%s\"", s)
		return 0, fmt.Errorf("unknown tapir RPZ action: \"%s\"", s)
	}
}

var ActionToCNAMETarget = map[Action]string{
	NXDOMAIN:  ".",
	NODATA:    "*.",
	DROP:      "rpz-drop.",
	WHITELIST: "rpz-passthru.",
	REDIRECT:  "what-to-do-about-this",
}

var ActionToString = map[Action]string{
	NXDOMAIN:  "NXDOMAIN",
	NODATA:    "NODATA",
	DROP:      "DROP",
	WHITELIST: "WHITELIST",
	REDIRECT:  "WHAT-TO-DO-ABOUT-REDIRECTS",
}

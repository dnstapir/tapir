/*
 * Copyright (c) DNS TAPIR
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

func SetTag(b, tag TagMask) TagMask    { return b | tag }
func ClearTag(b, tag TagMask) TagMask  { return b &^ tag }
func ToggleTag(b, tag TagMask) TagMask { return b ^ tag }
func HasTag(b, tag TagMask) bool       { return b & tag != 0 }

func (tm *TagMask) SetTag(tag TagMask) 	    { *tm = *tm | tag }
func (tm *TagMask) ClearTag(tag TagMask)    { *tm = *tm &^ tag }
func (tm *TagMask) ToggleTag(tag TagMask)   { *tm = *tm ^ tag }
func (tm *TagMask) HasTag(tag TagMask) bool { return *tm & tag != 0 }

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
 	 case "foo":
 	      res = SetTag(res, Foo)
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
	      return res, fmt.Errorf("Unknown tapir tag: \"%s\"", s)
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
      UnknownAction
)

func (tn *TapirName) HasAction(action Action) bool { return tn.Action & action != 0 }

func StringToAction(s string) (Action, error) {
     	 switch strings.ToLower(s) {
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
	      return 0, fmt.Errorf("Unknown tapir RPZ action: \"%s\"", s)
	 }
     return 0, nil
}
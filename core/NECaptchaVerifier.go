package core

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/os/gtime"
	"github.com/gogf/gf/util/grand"
	"sort"
	"strconv"
)

// @ref: https://github.com/yidun/captcha-php-demo
// @ref: http://support.dun.163.com/documents/15588062143475712?docId=69218161355051008
const (
	YunDunCaptchaApiVersion = "v2"
	YunDunCaptchaApiURL     = "http://c.dun.163yun.com/api/v2/verify"
)

type NECaptchaVerifier struct {
	CaptchaID  string
	SecretPair SecretPair
}

type NEResponse struct {
	Msg    string `json:"msg"`
	Result bool   `json:"result"`
	Error  int    `json:"error"`
}

// 发起二次校验请求
// @param validate string 二次校验数据
// @param user 用户信息
func (that *NECaptchaVerifier) Verify(validate string, user string) (*NEResponse, error) {
	params := map[string]string{}
	params["captchaId"] = that.CaptchaID
	params["validate"] = validate
	params["user"] = user
	params["secretId"] = that.SecretPair.SecretId
	params["version"] = YunDunCaptchaApiVersion
	// time in millisecond
	params["timestamp"] = strconv.FormatInt(gtime.Now().UnixNano(), 10)
	params["nonce"] = grand.S(32)
	params["signature"] = genSignature(that.SecretPair.SecretKey, params)
	response := ghttp.PostContent(YunDunCaptchaApiURL, params)
	result := &NEResponse{}
	fmt.Println(response)

	// json deocode
	err := gjson.DecodeTo(response, &result)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("json decode error: %s", err.Error()))
	}
	return result, err
}

// 计算参数签名
// @param secretKey 密钥对key
// @param params 请求参数
func genSignature(secretKey string, params map[string]string) string {
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	buf := bytes.NewBufferString("")
	for _, key := range keys {
		buf.WriteString(key + params[key])
	}
	buf.WriteString(secretKey)
	fmt.Printf("signature=%s\n", buf.String())

	has := md5.Sum(buf.Bytes())
	return fmt.Sprintf("%x", has)
}

package main

import (
	"errors"
	"fmt"
	"gf-necaptcha/core"
)

type GFNECaptcha struct {
	Validate string // $_POST["NECaptchaValidate"]
	Data     string // "{'user':123456}"
}

func New(validate, data string) *GFNECaptcha {
	return &GFNECaptcha{
		Validate: validate,
		Data:     data,
	}
}

func (that *GFNECaptcha) Verify(appId, appSecretId, appSecretKey string) (bool, error) {
	var verifier = core.NECaptchaVerifier{
		CaptchaID:  appId,
		SecretPair: *core.NewSecretPair(appSecretId, appSecretKey),
	}
	fmt.Println(verifier)
	if len(that.Validate) < 1 {
		return false, errors.New("NECaptchaValidate can't be empty")
	}
	result, err := verifier.Verify(that.Validate, that.Data)
	fmt.Println(result)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	// {"msg":"PARAM_ERROR","result":false,"error":419}
	if !result.Result {
		return result.Result, errors.New(
			fmt.Sprintf("error:%d, msg:%s", result.Error, result.Msg))
	}
	// {"msg":OK, "result":true, "error"0}
	return result.Result, nil

}

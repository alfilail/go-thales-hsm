package gothaleshsm

import "github.com/alfilail/go-thales-hsm/service"

type Hsm struct {
	HsmClient *service.HsmTcpClient
}

func NewClient(servAddr, zpk string) *Hsm {
	return &Hsm{HsmClient: &service.HsmTcpClient{
		ServAddr:   servAddr,
		Zpk:        zpk,
		HsmCmdHead: "TLBG",
		BufferSize: 1024,
	}}
}

func (c *Hsm) Encrypt(clearPin, cardNumber string) (string, error) {
	c.HsmClient.DialTcp()
	defer c.HsmClient.Close()

	hsmCardNumber := cardNumber[len(cardNumber)-13 : len(cardNumber)-1]

	BAheader := service.BAClearPINtoLMK(clearPin, hsmCardNumber)
	BAHsmRes, errBA := c.HsmClient.SendRawToHSM(BAheader)
	if errBA != nil {
		return "", errBA
	}
	PINunderLMK := service.CommonResponse(BAHsmRes)

	JGheader := service.JGPINLMKtoZPK(c.HsmClient.Zpk, 1, hsmCardNumber, PINunderLMK)
	JGHsmRes, errJG := c.HsmClient.SendRawToHSM(JGheader)
	if errJG != nil {
		return "", errJG
	}
	PINblock := service.CommonResponse(JGHsmRes)
	return PINblock, nil
}

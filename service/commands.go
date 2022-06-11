package service

import "fmt"

func ExcludeBigendianHdr(hsmCmdHead, hdr string) string {
	aData := hsmCmdHead + hdr
	formattedHdr := fmt.Sprintf("%c", len(aData)>>8) + fmt.Sprintf("%c", len(aData)&255) + aData
	return formattedHdr
}

func BAClearPINtoLMK(pin, hsmCardNumber string) string {
	return "BA" + pin + "F" + hsmCardNumber
}

func JAGenRandomPIN(hsmCardNumber string, pinLength int) string {
	return "JA" + hsmCardNumber + fmt.Sprintf("%02d", pinLength)
}

func JGPINLMKtoZPK(zpk string, pinFmt int, hsmCardNumber string, pinLMK string) string {
	return "JG" + zpk + fmt.Sprintf("%02d", pinFmt) + hsmCardNumber + pinLMK
}

func JEPINZPKtoLMK(zpk string, pinBlock string, pinFmt int, hsmCardNumber string) string {
	return "JE" + zpk + pinBlock + fmt.Sprintf("%02d", pinFmt) + hsmCardNumber
}

func NGPINLMKtoClear(hsmCardNumber, pinLMK string) string {
	return "NG" + hsmCardNumber + pinLMK
}

func CommonResponse(raw string) string {
	return raw[9:]
}

func NGResponse(raw string) string {
	return raw[9:15]
}

func ErrDesc(argument string) string {
	desc := map[string]string{
		"00": "No error",
		"01": "Verification failure or warning of imported key parity error",
		"02": "Key inappropriate length for algorithm",
		"04": "Invalid key type code",
		"05": "Invalid key length flag",
		"10": "Source key parity error",
		"11": "Destination key parity error or key all zeros",
		"12": "Contents of user storage not available. Reset, power-down or overwrite",
		"13": "Invalid LMK Identifier",
		"14": "PIN encrypted under LMK pair 02-03 is invalid",
		"15": "Invalid input data (invalid format, invalid characters, or not enough data provided)",
		"16": "Console or printer not ready or not connected",
		"17": "HSM not in the Authorised state, or not enabled for clear PIN output, or both",
		"18": "Document format definition not loaded",
		"19": "Specified Diebold Table is invalid",
		"20": "PIN block does not contain valid values",
		"21": "Invalid index value, or index/block count would cause an overflow condition",
		"22": "Invalid account number",
		"23": "Invalid PIN block format code",
		"24": "PIN is fewer than 4 or more than 12 digits in length",
		"25": "Decimalisation Table error",
		"26": "Invalid key scheme",
		"27": "Incompatible key length",
		"28": "Invalid key type",
		"29": "Key function not permitted",
		"30": "Invalid reference number",
		"31": "Insufficient solicitation entries for batch",
		"33": "LMK key change storage is corrupted",
		"39": "Fraud detection",
		"40": "Invalid checksum",
		"41": "Internal hardware/software error: bad RAM, invalid error codes, etc.",
		"42": "DES failure",
		"47": "Algorithm not licensed",
		"49": "Private key error, report to supervisor",
		"51": "Invalid message header",
		"65": "Transaction Key Scheme set to None",
		"67": "Command not licensed",
		"68": "Command has been disabled",
		"69": "PIN block format has been disabled",
		"74": "Invalid digest info syntax (no hash mode only)",
		"75": "Single length key masquerading as double or triple length key",
		"76": "Public key length error",
		"77": "Clear data block error",
		"78": "Private key length error",
		"79": "Hash algorithm object identifier error",
		"80": "Data length error. The amount of MAC data (or other data) is greater than or less than the expected amount.",
		"81": "Invalid certificate header",
		"82": "Invalid check value length",
		"83": "Key block format error",
		"84": "Key block check value error",
		"85": "Invalid OAEP Mask Generation Function",
		"86": "Invalid OAEP MGF Hash Function",
		"87": "OAEP Parameter Error",
	}
	return desc[argument]
}

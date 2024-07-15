package context

const (
	UpFunctionFeaturesBucp  uint16 = 1
	UpFunctionFeaturesDdnd  uint16 = 1 << 1
	UpFunctionFeaturesDlbd  uint16 = 1 << 2
	UpFunctionFeaturesTrst  uint16 = 1 << 3
	UpFunctionFeaturesFtup  uint16 = 1 << 4
	UpFunctionFeaturesPfdm  uint16 = 1 << 5
	UpFunctionFeaturesHeeu  uint16 = 1 << 6
	UpFunctionFeaturesTreu  uint16 = 1 << 7
	UpFunctionFeaturesEmpu  uint16 = 1 << 8
	UpFunctionFeaturesPdiu  uint16 = 1 << 9
	UpFunctionFeaturesUdbc  uint16 = 1 << 10
	UpFunctionFeaturesQuoac uint16 = 1 << 11
	UpFunctionFeaturesTrace uint16 = 1 << 12
	UpFunctionFeaturesFrrt  uint16 = 1 << 13
	UpFunctionFeaturesPfde  uint16 = 1 << 14
	UpFunctionFeaturesEpfar uint16 = 1 << 15
)

// Supported Feature-1
const (
	UpFunctionFeatures1Dprda uint16 = 1
	UpFunctionFeatures1Adpdp uint16 = 1 << 1
	UpFunctionFeatures1Ueip  uint16 = 1 << 2
	UpFunctionFeatures1Sset  uint16 = 1 << 3
	UpFunctionFeatures1Mnop  uint16 = 1 << 4
	UpFunctionFeatures1Mte   uint16 = 1 << 5
	UpFunctionFeatures1Bundl uint16 = 1 << 6
	UpFunctionFeatures1Gcom  uint16 = 1 << 7
	UpFunctionFeatures1Mpas  uint16 = 1 << 8
	UpFunctionFeatures1Rttl  uint16 = 1 << 9
	UpFunctionFeatures1Vtime uint16 = 1 << 10
	UpFunctionFeatures1Norp  uint16 = 1 << 11
	UpFunctionFeatures1Iptv  uint16 = 1 << 12
	UpFunctionFeatures1Ip6pl uint16 = 1 << 13
	UpFunctionFeatures1Tscu  uint16 = 1 << 14
	UpFunctionFeatures1Mptcp uint16 = 1 << 15
)

// Supported Feature-2
const (
	UpFunctionFeatures2Atsssll uint16 = 1
	UpFunctionFeatures2Qfqm    uint16 = 1 << 1
	UpFunctionFeatures2Gpqm    uint16 = 1 << 2
	UpFunctionFeatures2Mtedt   uint16 = 1 << 3
	UpFunctionFeatures2Ciot    uint16 = 1 << 4
	UpFunctionFeatures2Ethar   uint16 = 1 << 5
	UpFunctionFeatures2Ddds    uint16 = 1 << 6
	UpFunctionFeatures2Rds     uint16 = 1 << 7
	UpFunctionFeatures2Rttwp   uint16 = 1 << 8
)

type UPFunctionFeatures struct {
	SupportedFeatures  uint16
	SupportedFeatures1 uint16
	SupportedFeatures2 uint16
}

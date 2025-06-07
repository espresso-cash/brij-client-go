package common

type RampType string

const (
	RampTypeOnRamp  RampType = "RAMP_TYPE_ON_RAMP"
	RampTypeOffRamp RampType = "RAMP_TYPE_OFF_RAMP"
)

type Amount struct {
	Value    float64
	Currency string
}

variable "VERSION" { default = "0.1.0" }
variable "SOURCE_DATE_EPOCH" { default = "0" }

group "default" {
  targets = ["control", "relay", "console"]
}

target "peerward-base" {
  context = "../.."
  dockerfile = "packaging/docker/peerward.Dockerfile"
  args = {
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    VERSION = VERSION
  }
  platforms = ["linux/amd64", "linux/arm64"]
  attest = ["type=sbom", "type=provenance,mode=max"]
}

target "control" {
  inherits = ["peerward-base"]
  target = "control"
  tags = ["ghcr.io/dayrai/peerward:${VERSION}-control"]
}

target "relay" {
  inherits = ["peerward-base"]
  target = "relay"
  tags = ["ghcr.io/dayrai/peerward:${VERSION}-relay"]
}

target "console" {
  context = "../.."
  dockerfile = "packaging/docker/console.Dockerfile"
  target = "console"
  args = {
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
    VERSION = VERSION
  }
  platforms = ["linux/amd64", "linux/arm64"]
  tags = ["ghcr.io/dayrai/peerward:${VERSION}-console"]
  attest = ["type=sbom", "type=provenance,mode=max"]
}

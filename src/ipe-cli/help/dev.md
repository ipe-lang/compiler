The development inner loop — build, run, and watch with Debug.* on and no jail.
`ipe dev` runs your program with your full user permissions and checks no capabilities. Run external packages only through `ipe release`, which infers capabilities, asks for consent and runs native code jailed.

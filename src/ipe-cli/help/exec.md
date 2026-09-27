Run a built artifact, jailing native-bearing code to its embedded capability floor.

```
ipe exec [<artifact-dir>]
```

## Arguments

The build output directory to run (defaults to out/rust). A native-bearing artifact is confined to its embedded capability floor; a pure Ipê artifact runs directly.

## Options

- `[-- <args>...]` — forward <args> to the artifact

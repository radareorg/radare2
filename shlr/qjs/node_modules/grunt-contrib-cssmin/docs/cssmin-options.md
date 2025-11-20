# Options

## banner

Type: `String`
Default: `null`

Prefix the compressed source with the given banner, with a linebreak inbetween.

## keepSpecialComments

Type: `String` `Number`
Default: `'*'`

To keep or remove special comments, exposing the underlying option from [clean-css](https://github.com/GoalSmashers/clean-css).. `'*'` for keeping all (default), `1` for keeping first one, `0` for removing all.

## report
Choices: `false`, `'min'`, `'gzip'`
Default: `false`

Either do not report anything, report only minification result, or report minification and gzip results.
This is useful to see exactly how well clean-css is performing but using `'gzip'` will make the task take 5-10x longer to complete.

Example ouput using `'gzip'`:

```
Original: 198444 bytes.
Minified: 101615 bytes.
Gzipped:  20084 bytes.
```
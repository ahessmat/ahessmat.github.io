#### Exploiting PHP Deserialization

This section was pretty straightforward. Since values from deserialized data get passed to various other functions in code, this section focused on showing how malicious values in that deserialized data can flow into PHP code to do harm. Some of the vulnerabilities are demonstrated as manipulated logic (i.e. `Object Injection`) others as malicious code injection (being passed to functions like `shell_exec()` for RCE or `mysqli_query()` for SQLi). The section also looks at deserialization through PHAR archives (very neat, though somewhat niche) and some tools to help automate the malicious serialization process. The section closes out by highlighting an interesting tool - `phpggc` - which can automate the process of crafting malicious serialized PHP payloads.

#### Exploiting Python Deserialization

This section parallels the previous one, but this time looking at the `pickle` library more narrowly.

#### Defending against Deserialization Attacks

This section is brief (containing only 2 subsections), with only one exercise that you can trivially perform without needing to download the supplied source code (or really go through the motions described). I think that this section would benefit from a better set of exercises, because being able to effectively remediate these issues is pretty important in the professional space.
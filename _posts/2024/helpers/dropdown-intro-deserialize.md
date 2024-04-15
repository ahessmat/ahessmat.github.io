#### Exploiting PHP Deserialization

This section was pretty straightforward. Since values from deserialized data get passed to various other functions in code, this section focused on showing how malicious values in that deserialized data can flow into PHP code to do harm. Some of the vulnerabilities are demonstrated as manipulated logic (i.e. `Object Injection`) others as malicious code injection (being passed to functions like `shell_exec()` for RCE or `mysqli_query()` for SQLi). The section also looks at deserialization through PHAR archives (very neat, though somewhat niche) and some tools to help automate the malicious serialization process. My one small hang-up with the section was the **RCE: Magic Methods** subsection, which made extensive efforts to highlight PHP's overridable magic methods as somehow being particularly susceptible to deserialization attacks; reading through the material however, there wasn't anything inately/inherently more dangerous: the vulnerable elements were in custom code, which could appear anywhere - inside or out of magic methods.

#### Exploiting Python Deserialization


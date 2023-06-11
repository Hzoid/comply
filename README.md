# Comply
Stop wasting time cracking with useless wordlists! Make them comply.

This is a wordlist manipulation tool written in C#. It contains a profile (--default) which reduces wordlists down to the default [windows password policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements).

I wrote this tool because I found myself struggling to whittle down wordlists for cracking active directory account hashes. Since wordlists such as [rockyou.txt](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz) contain passwords that definitely won't be accepted by active directory's default configuration, I found that a lot of (actual and computational) time was wasted on candidates that would never get matches.

Organically, the program grew to support other filters, such as known minimum/maximum/exact length, character inclusion or exclusion, and more. Feel free to commit / request features!

# Prerequisites
This program is written in .NET 7.0 - you can either compile it yourself or use the [releases](https://github.com/Hzoid/comply/releases) page to download either the Linux or Windows pre-compiled binaries.

To compile yourself, using VSCode:
```
# *nix
dotnet publish --configuration Release --runtime linux-x64 --self-contained true -p:PublishSingleFile=true

# Windows
dotnet publish --configuration Release --self-contained true -p:PublishSingleFile=true
```
# Examples

## Standard Examples
Filter by passwords conforming with the default windows password policy, and output to new_wordlist.txt
```
./comply --default --output ./new_wordlist.txt rockyou.txt
```

Filter by only passwords with an exact length of 12, use 16 threads (to stdout)
```
./comply --length=12  --threads 16 rockyou.txt
```

Filter by only passwords that start with "password" (case insensitive) (to stdout)
```
./comply --starts-with "password" --ignore-case rockyou.txt
```

Filter by passwords with a minimum length of 8, a maximum length of 14, that contain any of "@, #, !, ^" (to stdout)
```
./comply --min-length=8 --max-length=14 --include "@,#,!,^" rockyou.txt
```

Filter by passwords that contain all of "@, #, !, ^", using 32 threads (to stdout)
```
./comply --threads=32 --include-exclusive "@,#,!,^" rockyou.txt
```

## Piping Examples
It is also possible to chain multiple comply statements together, since --stdin is supported. Other options used with the --default parameter may not produce the best results because of how the code is written. It is instead recommended to chain --default before or after the use of other options.

Multiple filters plus --default, and output to new_wordlist.txt
```
cat rockyou.txt | ./comply --stdin --threads=32 --include-exclusive "#,%,@" | ./comply --stdin --threads=32 --default --output ./new_wordlist.txt
```

# USAGE
```
Comply 1.0.0
Copyright (C) 2023 Comply

./comply [OPTIONS] --stdin/--path=WORDLIST

  -d, --default          (Default: false) Apply the default windows password complexity requirement rules. Compatible with other filters.

  -n, --names            List of names, separated by commas.

  -v, --verbose          (Default: false) Display statistics after filtering the wordlist.

  -p, --path             Wordlist to apply fitlers to

  --stdin                (Default: false) Read wordlist from standard input.

  --min-length           Minimum password length to allow.

  --max-length           Maximum password length to allow.

  -u, --uppercase        Minimum uppercase characters to allow.

  -l, --length           Allow only entries containing this exact length.

  -t, --threads          Number of threads to use.

  --starts-with          Only allow entries that start with this string.

  --ends-with            Only allow entries that end with this string.

  --ignore-case          (Default: true) (Default: true) Ignore case when using --starts-with and --ends-with

  -e, --exclude          Exclude entries containing any of these characters.

  -i, --include          Include only entries containing at least one of these characters.

  --include-exclusive    Include entries containing ALL of the specified characters.

  -o, --output           Output file to write the updated wordlist to.

  --help                 Display this help screen.

  --version              Display version information.
```

# TODO
* Implement means of importing password policy data to create custom filtration profiles
* Further validation checks / bug fixes

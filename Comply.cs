using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using CommandLine;

namespace comply
{
    class Program
    {
        public class Options
        {
            [Option('d', "default", Default = false, HelpText = "Apply the default windows password complexity requirement rules. Compatible with other filters.")]
            public bool IsDefault { get; set; }

            [Option('n', "names", Separator = ',', HelpText = "List of names, separated by commas.")]
            public IEnumerable<string> Names { get; set; }

            [Option('v', "verbose", Default = false, HelpText = "Display statistics after filtering the wordlist.")]
            public bool Verbose { get; set; }

            [Option('p', "path", HelpText = "Wordlist to apply fitlers to")]
            public string FilePath { get; set; }

            [Option("stdin", HelpText = "Read wordlist from standard input.", Default = false)]
            public bool UseStandardInput { get; set; }

            [Option("min-length", HelpText = "Minimum password length to allow.")]
            public int? MinLength { get; set; }

            [Option("max-length", HelpText = "Maximum password length to allow.")]
            public int? MaxLength { get; set; }

            [Option('u', "uppercase", HelpText = "Minimum uppercase characters to allow.")]
            public int? UppercaseCount { get; set; }

            [Option('l', "length", HelpText = "Allow only entries containing this exact length.")]
            public int? Length { get; set; }

            [Option('t', "threads", HelpText = "Number of threads to use.")]
            public int? Threads { get; set; }

            [Option("starts-with", HelpText = "Only allow entries that start with this string.")]
            public string StartsWith { get; set; }

            [Option("ends-with", HelpText = "Only allow entries that end with this string.")]
            public string EndsWith { get; set; }

            [Option("ignore-case", Default = true, HelpText = "(Default: true) Ignore case when using --starts-with and --ends-with")]
            public bool IgnoreCase { get; set; }

            [Option('e', "exclude", Separator = ',', HelpText = "Exclude entries containing any of these characters.")]
            public IEnumerable<char> Exclude { get; set; }

            [Option('i', "include", Separator = ',', HelpText = "Include only entries containing at least one of these characters.")]
            public IEnumerable<char> Include { get; set; }

            [Option("include-exclusive", Separator = ',', HelpText = "Include entries containing ALL of the specified characters.")]
            public IEnumerable<char> IncludeExclusive { get; set; }

            [Option('o', "output", HelpText = "Output file to write the updated wordlist to.")]
            public string OutputFilePath { get; set; }
        }

        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options =>
                {
                    // VALIDATION FOR COMMAND LINE ARGUMENTS
                    if ((options.UseStandardInput && !string.IsNullOrEmpty(options.FilePath)) || (!options.UseStandardInput && string.IsNullOrEmpty(options.FilePath)))
                    {
                        Console.Error.WriteLine("Error: You must specify exactly one of --stdin or --path.");
                        Environment.Exit(0);
                    }

                    if (options.Length.HasValue && (options.MinLength.HasValue || options.MaxLength.HasValue))
                    {
                        Console.Error.WriteLine("Error: If 'length' is specified, neither 'min-length' nor 'max-length' should be supplied.");
                        Environment.Exit(0);
                    }

                    if (options.MinLength.HasValue && options.MaxLength.HasValue && options.MinLength > options.MaxLength)
                    {
                        Console.Error.WriteLine("Error: 'min-length' cannot be larger than 'max-length'.");
                        Environment.Exit(0);
                    }

                    if (options.UppercaseCount.HasValue && options.UppercaseCount < 0)
                    {
                        Console.Error.WriteLine("Error: 'uppercase' cannot be smaller than 0.");
                        Environment.Exit(0);
                    }

                    if (options.UppercaseCount.HasValue && options.MinLength.HasValue && options.UppercaseCount < options.MinLength)
                    {
                        Console.Error.WriteLine("Error: 'uppercase' cannot be smaller than 'min-length'.");
                        Environment.Exit(0);
                    }

                    if (options.UppercaseCount.HasValue && options.MaxLength.HasValue && options.UppercaseCount > options.MaxLength)
                    {
                        Console.Error.WriteLine("Error: 'uppercase' cannot be larger than 'max-length'.");
                        Environment.Exit(0);
                    }

                    if (options.UppercaseCount.HasValue && options.Length.HasValue && options.UppercaseCount > options.Length)
                    {
                        Console.Error.WriteLine("Error: 'uppercase' cannot be larger than 'length'.");
                        Environment.Exit(0);
                    }

                    if (!string.IsNullOrEmpty(options.FilePath) && (!File.Exists(options.FilePath) || !HasReadPermissionOnFile(options.FilePath)))
                    {
                        Console.Error.WriteLine("Error: The provided 'path' must be a valid and readable file.");
                        Environment.Exit(0);
                    }

                    if (options.Threads.HasValue && options.Threads < 1)
                    {
                        Console.Error.WriteLine("Error: 'threads' must be 1 or more.");
                        Environment.Exit(0);
                    }
                    if (!string.IsNullOrEmpty(options.StartsWith) && 
                        ((options.MaxLength.HasValue && options.StartsWith.Length > options.MaxLength) || 
                        (options.Length.HasValue && options.StartsWith.Length > options.Length)))
                    {
                        Console.Error.WriteLine("Error: 'starts-with' string cannot be longer than 'max-length' or 'length'.");
                        Environment.Exit(0);
                    }

                    if (!string.IsNullOrEmpty(options.EndsWith) && 
                        ((options.MaxLength.HasValue && options.EndsWith.Length > options.MaxLength) || 
                        (options.Length.HasValue && options.EndsWith.Length > options.Length)))
                    {
                        Console.Error.WriteLine("Error: 'ends-with' string cannot be longer than 'max-length' or 'length'.");
                        Environment.Exit(0);
                    }

                    if (options.Include != null && options.Include.Any() && options.IncludeExclusive != null && options.IncludeExclusive.Any())
                    {
                        Console.Error.WriteLine("Error: Options 'include' and 'include-exclusive' are mutually exclusive");
                        Environment.Exit(0);
                    }

                    if (options.Include != null && options.Include.Any() && options.Exclude != null && options.Include.Any(c => options.Exclude.Contains(c)))
                    {
                        Console.Error.WriteLine("Error: Characters specified in 'include' cannot be present in 'exclude'.");
                        Environment.Exit(0);
                    }

                    if (options.IncludeExclusive != null && options.IncludeExclusive.Any() && options.Exclude != null && options.IncludeExclusive.Any(c => options.Exclude.Contains(c)))
                    {
                        Console.Error.WriteLine("Error: Characters specified in 'include-exclusive' cannot be present in 'exclude'.");
                        Environment.Exit(0);
                    }

                    if (options.Exclude != null && options.Exclude.Any())
                    {
                        if (!string.IsNullOrEmpty(options.StartsWith) && options.Exclude.Any(c => options.StartsWith.Contains(c)))
                        {
                            Console.Error.WriteLine("Error: Characters in 'exclude' cannot be present in 'starts-with' string.");
                            Environment.Exit(0);
                        }

                        if (!string.IsNullOrEmpty(options.EndsWith) && options.Exclude.Any(c => options.EndsWith.Contains(c)))
                        {
                            Console.Error.WriteLine("Error: Characters in 'exclude' cannot be present in 'ends-with' string.");
                            Environment.Exit(0);
                        }
                    }

                    int threadsCount = options.Threads.HasValue && options.Threads.Value > 0 ? options.Threads.Value : 1;

                    // Read the file lines into memory
                    List<string> allLines = new List<string>();

                    // Check if --stdin option is used
                    if (options.UseStandardInput)
                    {
                        // Read from standard input
                        if (Console.IsInputRedirected)
                        {
                            string line;
                            while ((line = Console.ReadLine()) != null)
                            {
                                allLines.Add(line);
                            }
                        }
                        else
                        {
                            Console.Error.WriteLine("Error: No data provided via standard input.");
                            Environment.Exit(0);
                        }
                    }
                    else
                    {
                        // Read from file
                        try
                        {
                            allLines = File.ReadAllLines(options.FilePath).ToList();
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Error reading file: {ex.Message}");
                            Environment.Exit(0);
                        }
                    }

                    // Calculate chunk size
                    int chunkSize = (allLines.Count + threadsCount - 1) / threadsCount;

                    // Split lines into arrays
                    var chunkedArrays = new List<string[]>();
                    for (int i = 0; i < allLines.Count; i += chunkSize)
                    {
                        var chunk = allLines.Skip(i).Take(chunkSize).ToArray();
                        chunkedArrays.Add(chunk);
                    }

                    int removedEntriesCount = 0;
                    object lockObj = new object();

                    // Collect the filtered chunks
                    var filteredChunks = new ConcurrentBag<IEnumerable<string>>();

                    // Create and start threads
                    var threads = new List<Thread>();
                    for (int i = 0; i < chunkedArrays.Count; i++)
                    {
                        var chunk = chunkedArrays[i];
                        var thread = new Thread(() =>
                        {
                            var filteredChunk = ProcessChunk(chunk, options, lockObj, ref removedEntriesCount);
                            filteredChunks.Add(filteredChunk);
                        });
                        threads.Add(thread);
                        thread.Start();
                    }

                    // Wait for all threads to complete
                    foreach (var thread in threads)
                    {
                        thread.Join();
                    }

                    // Reassemble the wordlist
                    var reassembledWordList = filteredChunks.SelectMany(chunk => chunk).ToList();

                    // Output to file or stdout
                    string newWordListPath;
                    if (!string.IsNullOrEmpty(options.OutputFilePath) && HasWritePermissionOnFile(options.OutputFilePath))
                    {
                        File.WriteAllLines(options.OutputFilePath, reassembledWordList);
                        newWordListPath = options.OutputFilePath;
                    }
                    else
                    {
                        foreach (var word in reassembledWordList)
                        {
                            Console.WriteLine(word);
                        }
                        newWordListPath = "";
                    }

                    if (options.Verbose)
                    {
                        Console.WriteLine($"{removedEntriesCount} entries from {options.FilePath} were removed.");
                        Console.WriteLine($"Wordlist {newWordListPath} contains {reassembledWordList.Count}.");
                    }
                });
        }

        // This function does all of the filtering of the wordlist.
        static IEnumerable<string> ProcessChunk(string[] chunk, Options options, object lockObj, ref int removedEntriesCount)
        {
            string[] names = options.Names?.SelectMany(name => name.Split(new char[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)).ToArray();

            StringComparison stringComparison = options.IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            bool warnedOverwrite = false;

            var filteredChunk = chunk.Where(entry =>
            {
                bool isPasswordValid = true;
                if (options.IsDefault)
                {
                    isPasswordValid = IsValidWindowsPassword(entry, names);
                }

                if (!options.IsDefault || (options.IsDefault && options.Length.HasValue && entry.Length == options.Length))
                {
                    if (options.Length.HasValue && entry.Length != options.Length)
                    {
                        isPasswordValid = false;
                    }
                    else if (options.IsDefault && options.Length.HasValue && !warnedOverwrite)
                    {
                        Console.Error.WriteLine("Warning: You are overwriting the default Windows password policy filtering options.");
                        warnedOverwrite = true;
                    }
                }

                if (!options.IsDefault || (options.IsDefault && options.MinLength.HasValue && entry.Length >= options.MinLength))
                {
                    if (options.MinLength.HasValue && entry.Length < options.MinLength)
                    {
                        isPasswordValid = false;
                    }
                    else if (options.IsDefault && options.MinLength.HasValue && !warnedOverwrite)
                    {
                        Console.Error.WriteLine("Warning: You are overwriting the default Windows password policy filtering options.");
                        warnedOverwrite = true;
                    }
                }

                if (!options.IsDefault || (options.IsDefault && options.MaxLength.HasValue && entry.Length <= options.MaxLength))
                {
                    if (options.MaxLength.HasValue && entry.Length > options.MaxLength)
                    {
                        isPasswordValid = false;
                    }
                    else if (options.IsDefault && options.MaxLength.HasValue && !warnedOverwrite)
                    {
                        Console.Error.WriteLine("Warning: You are overwriting the default Windows password policy filtering options.");
                        warnedOverwrite = true;
                    }
                }

                // Include/Exclude/Include-Exclusive conditions
                bool excludeCondition = options.Exclude == null || !options.Exclude.Any(c => entry.Contains(c));
                bool includeCondition;
                bool includeExclusiveCondition;

                // Make sure --include-exclusive and --include do not conflict
                if (options.IncludeExclusive != null)
                {
                    // Use --include-exclusive option
                    includeExclusiveCondition = options.IncludeExclusive.All(c => entry.Contains(c));
                    includeCondition = true; // Make includeCondition true as --include-exclusive takes precedence
                }
                else
                {
                    // Use --include option
                    includeCondition = options.Include == null || options.Include.Any(c => entry.Contains(c));
                    includeExclusiveCondition = true; // Make includeExclusiveCondition true as --include is being used
                }

                return isPasswordValid &&
                    (options.UppercaseCount == null || entry.Count(char.IsUpper) >= options.UppercaseCount) &&
                    (string.IsNullOrEmpty(options.StartsWith) || entry.StartsWith(options.StartsWith, stringComparison)) &&
                    (string.IsNullOrEmpty(options.EndsWith) || entry.EndsWith(options.EndsWith, stringComparison)) &&
                    excludeCondition &&
                    includeCondition &&
                    includeExclusiveCondition;
            }).ToArray();

            // Counter for --verbose statistics
            lock (lockObj)
            {
                removedEntriesCount += (chunk.Length - filteredChunk.Length);
            }

            return filteredChunk;
        }

        // This function defines the default windows password policy
        static bool IsValidWindowsPassword(string password, string[] names)
        {
            if (names != null)
            {
                foreach (var name in names)
                {
                    if (name.Length >= 3 && password.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return false;
                    }
                }
            }

            // The existing categories for windows default password policy
            int categories = 0;
            if (Regex.IsMatch(password, "[A-Z\u00C0-\u00D6\u00D8-\u00DE]")) categories++;
            if (Regex.IsMatch(password, "[a-z\u00DF-\u00F6\u00F8-\u00FF]")) categories++;
            if (Regex.IsMatch(password, "[0-9]")) categories++;
            if (Regex.IsMatch(password, "[~!@#$%^&*_\\-+=`|\\\\(){}\\[\\]:;\"'<>,.?/]")) categories++;

            return categories >= 3 && password.Length >= 6;
        }
        // Is file readable
        static bool HasReadPermissionOnFile(string filePath)
        {
            try
            {
                using (FileStream fs = File.Open(filePath, FileMode.Open, FileAccess.Read))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        // Is file writable
        static bool HasWritePermissionOnFile(string filePath)
        {
            try
            {
                using (FileStream fs = File.Open(filePath, FileMode.OpenOrCreate, FileAccess.Write))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}

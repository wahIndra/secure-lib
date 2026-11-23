package io.github.wahindra.secure.injection;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;
import io.github.wahindra.secure.detect.DetectionResult;
import io.github.wahindra.secure.detect.Rule;
import io.github.wahindra.secure.detect.Rule.View;
import io.github.wahindra.secure.detect.RuleBasedDetector;
import io.github.wahindra.secure.detect.Severity;

import static io.github.wahindra.secure.detect.Rule.anyOf;

import java.util.ArrayList;
import java.util.List;

/**
 * Signature detector for SQL injection probes, tuned for PostgreSQL but covering MySQL,
 * MSSQL, Oracle and SQLite techniques too.
 *
 * <p>This is a second line of defence for monitoring and blocking scanners. The fix for
 * SQL injection is parameterized queries ({@code PreparedStatement}); see {@link SafeSql}
 * for the parts of a query that cannot be parameterized.
 */
public final class SqlInjectionDetector extends RuleBasedDetector {

    private static final OwaspCategory C = OwaspCategory.INJECTION;
    // Quoted literals are length-bounded so a long unterminated quote cannot be rescanned from every OR/AND.
    private static final String LIT = "(?:\\d+(?:\\.\\d+)?|'[^']{0,100}'|\"[^\"]{0,100}\"|true|false|null)";

    private static final SqlInjectionDetector DEFAULT = new SqlInjectionDetector(defaultRules());

    public SqlInjectionDetector(List<Rule> rules) {
        super(rules);
    }

    public static SqlInjectionDetector defaults() {
        return DEFAULT;
    }

    /** Throws if the input looks like SQL injection. */
    public void assertSafe(String input) {
        DetectionResult r = inspect(input);
        if (r.isMalicious()) {
            throw new SecurityViolationException(C, "SQL injection pattern detected: " + r.getFindings());
        }
    }

    public static List<Rule> defaultRules() {
        List<Rule> r = new ArrayList<Rule>();

        // --- Time-based blind ---
        r.add(rule("SQLI_PG_SLEEP", Severity.HIGH, View.STRIPPED,
                "\\bpg_sleep(?:_for|_until)?\\s*\\(", "PostgreSQL pg_sleep time delay",
                anyOf("pg_sleep")));
        r.add(rule("SQLI_PG_SLEEP_SPLIT", Severity.HIGH, View.COMPACT,
                "pg_?sleep(?:_for|_until)?\\(", "pg_sleep split by spaces or comments",
                anyOf("sleep")));
        r.add(rule("SQLI_TIME_DELAY", Severity.HIGH, View.STRIPPED,
                "\\bsleep\\s*\\(\\s*\\d|\\bbenchmark\\s*\\(\\s*\\d|\\bwaitfor\\s+(?:delay|time)\\s+'"
                        + "|\\bdbms_pipe\\s*\\.\\s*receive_message|\\bdbms_lock\\s*\\.\\s*sleep|\\brandomblob\\s*\\(\\s*\\d{6,}",
                "Time delay function (MySQL/MSSQL/Oracle/SQLite)",
                anyOf("sleep", "benchmark", "waitfor", "dbms_", "randomblob")));

        // --- Boolean-based blind ---
        r.add(rule("SQLI_BOOLEAN_TAUTOLOGY", Severity.HIGH, View.STRIPPED,
                "(?:^|[\\s'\")(])(?:or|and|xor|\\|\\||&&)\\s*\\(*\\s*" + LIT + "\\s*\\)*\\s*"
                        + "(?:=|<>|!=|<=>|<=|>=|<|>|like\\b|is\\b)\\s*\\(*\\s*(?:" + LIT + "|'[^']{0,100}$|not\\s+null)",
                "Boolean condition such as OR 1=1 / AND 1=2",
                anyOf("or", "and", "xor", "||", "&&"), anyOf("=", "<", ">", "like", "is")));
        r.add(rule("SQLI_BOOLEAN_SUBQUERY", Severity.HIGH, View.STRIPPED,
                "(?:=|<>|!=|<|>|\\bin\\b|\\bis\\b|\\bexists\\b|\\bor\\b|\\band\\b|\\bnot\\b)\\s*\\(\\s*select\\b",
                "Comparison against a subquery (boolean/blind extraction)",
                anyOf("select")));
        r.add(rule("SQLI_CASE_WHEN", Severity.MEDIUM, View.STRIPPED,
                "\\bcase\\s+when\\b.{1,200}?\\bthen\\b", "CASE WHEN conditional",
                anyOf("case"), anyOf("then")));

        // --- Error-based ---
        r.add(rule("SQLI_CAST_ERROR", Severity.HIGH, View.STRIPPED,
                "\\bcast\\s*\\(\\s*\\(?\\s*(?:select\\b|version\\s*\\(|current_(?:user|database|setting|schema)\\b"
                        + "|user\\b|session_user\\b|database\\s*\\(|chr\\s*\\(|[a-z_]+\\s*\\|\\|)",
                "CAST of sensitive value to force a type error",
                anyOf("cast")));
        r.add(rule("SQLI_VERSION_CAST", Severity.HIGH, View.COMPACT,
                "version\\(\\)::|cast\\(\\(?(?:select)?version\\(\\)|@@version|\\bsqlite_version\\(",
                "version() cast or DB version disclosure",
                anyOf("version")));
        r.add(rule("SQLI_VERSION_CALL", Severity.MEDIUM, View.STRIPPED,
                "\\bversion\\s*\\(\\s*\\)", "version() call",
                anyOf("version")));
        r.add(rule("SQLI_TYPE_CAST", Severity.MEDIUM, View.STRIPPED,
                "\\)\\s*::\\s*(?:int|integer|numeric|bigint|smallint|text)\\b", "PostgreSQL :: cast after expression",
                anyOf("::")));
        r.add(rule("SQLI_ERROR_FUNCTION", Severity.HIGH, View.STRIPPED,
                "\\b(?:extractvalue|updatexml|exp\\s*\\(\\s*~|convert\\s*\\(\\s*int\\s*,|ctxsys\\s*\\.\\s*drithsx)",
                "Error-based extraction function",
                anyOf("extractvalue", "updatexml", "exp", "convert", "drithsx")));
        r.add(rule("SQLI_RAISE_EXCEPTION", Severity.HIGH, View.STRIPPED,
                "\\braise\\s+(?:exception|notice|warning|info|log|debug)\\s+(?:'|\\$|using\\b)",
                "PL/pgSQL RAISE EXCEPTION used to leak data",
                anyOf("raise")));
        r.add(rule("SQLI_RAISE_EXCEPTION_SPLIT", Severity.HIGH, View.COMPACT,
                "raise(?:exception|notice|warning)(?:'|\\$\\$|using)", "RAISE EXCEPTION split by spaces or comments",
                anyOf("raise")));
        r.add(rule("SQLI_RAISE_KEYWORD", Severity.MEDIUM, View.STRIPPED,
                "\\braise\\s+exception\\b", "RAISE EXCEPTION keyword",
                anyOf("raise")));

        // --- Dynamic / procedural execution ---
        r.add(rule("SQLI_EXECUTE_DYNAMIC", Severity.HIGH, View.STRIPPED,
                "\\bexec(?:ute)?\\s*(?:immediate\\s+)?(?:'|\\$[a-z_0-9]*\\$|format\\s*\\(|\\(\\s*['@]|@|sp_|xp_|master\\s*\\.)",
                "EXECUTE of a dynamic SQL string",
                anyOf("exec")));
        r.add(rule("SQLI_EXECUTE_DYNAMIC_SPLIT", Severity.HIGH, View.COMPACT,
                "execute(?:immediate)?(?:'|format\\(|\\$\\$)", "EXECUTE split by spaces or comments",
                anyOf("execute")));
        r.add(rule("SQLI_PG_DO_BLOCK", Severity.HIGH, View.STRIPPED,
                "\\bdo\\s*\\$[a-z_0-9]*\\$", "PostgreSQL anonymous DO $$ block",
                anyOf("do"), anyOf("$")));
        r.add(rule("SQLI_MSSQL_PROC", Severity.HIGH, View.STRIPPED,
                "\\b(?:xp_cmdshell|sp_executesql|sp_oacreate|sp_configure|xp_dirtree|xp_regread)\\b", "Dangerous MSSQL procedure",
                anyOf("xp_", "sp_")));

        // --- Structure ---
        r.add(rule("SQLI_UNION_SELECT", Severity.HIGH, View.STRIPPED,
                "\\bunion\\b(?:\\s+(?:all|distinct))?\\s*\\(*\\s*select\\b", "UNION SELECT",
                anyOf("union"), anyOf("select")));
        r.add(rule("SQLI_STACKED_QUERY", Severity.HIGH, View.STRIPPED,
                ";\\s*(?:select\\b.{0,200}?\\bfrom\\b|select\\s+(?:pg_sleep|version|current_|user\\b|\\d|null|\\*|case\\b)"
                        + "|insert\\s+into\\b|update\\s+[a-z_.\"]+\\s+set\\b|delete\\s+from\\b|truncate\\s+(?:table\\s+)?[a-z_]"
                        + "|drop\\s+(?:table|database|schema|view|function|user|role|index)\\b"
                        + "|alter\\s+(?:table|user|role|system|database)\\b|create\\s+(?:table|function|user|role|or\\s+replace)\\b"
                        + "|grant\\s+[a-z]|revoke\\s+[a-z]|exec(?:ute)?\\s|declare\\s+[@a-z]|do\\s*\\$|copy\\s+[a-z(]|shutdown\\b)",
                "Stacked (piggy-backed) statement",
                anyOf(";")));
        r.add(rule("SQLI_QUOTE_COMMENT_END", Severity.HIGH, View.DECODED,
                // "/*" and ";--" after a quote always run to the end of input, so they need no "$" (keeps this linear).
                "['\")]\\s*(?:/\\*|;\\s*--|(?:--[\\s-]*|#\\s*)$)", "Quote break-out followed by trailing comment (admin'--)",
                anyOf("'", "\"", ")"), anyOf("--", "#", "/*", ";")));
        r.add(rule("SQLI_QUOTE_COMMENT", Severity.MEDIUM, View.DECODED,
                "['\")]\\s*(?:--|#|/\\*)", "Quote followed by comment",
                anyOf("'", "\"", ")"), anyOf("--", "#", "/*")));
        r.add(rule("SQLI_INLINE_COMMENT", Severity.MEDIUM, View.DECODED,
                "[a-z0-9_]/\\*.{0,200}?\\*/[a-z0-9_(]|/\\*!\\d*", "Inline comment used as keyword separator",
                anyOf("/*")));
        r.add(rule("SQLI_ORDER_BY_PROBE", Severity.HIGH, View.STRIPPED,
                "\\border\\s+by\\s+\\d+\\s*(?:--|#)", "Column-count probe (ORDER BY n--)",
                anyOf("order")));
        r.add(rule("SQLI_ORDER_BY_NUMBER", Severity.MEDIUM, View.STRIPPED,
                "\\border\\s+by\\s+\\d+\\s*$|\\bgroup\\s+by\\b.{0,100}?\\bhaving\\b", "ORDER BY n / GROUP BY ... HAVING",
                anyOf("order", "having")));
        r.add(rule("SQLI_CHAR_CONCAT", Severity.MEDIUM, View.STRIPPED,
                "\\bchr\\s*\\(\\s*\\d+\\s*\\)\\s*\\|\\||\\bchar\\s*\\(\\s*\\d+(?:\\s*,\\s*\\d+){2,}", "CHR()/CHAR() string building",
                anyOf("chr", "char")));

        // --- Data and system access ---
        r.add(rule("SQLI_SYSTEM_CATALOG", Severity.MEDIUM, View.STRIPPED,
                "\\binformation_schema\\b|\\bpg_catalog\\b|\\bpg_(?:shadow|authid|user|roles|tables|namespace|proc|stat_activity)\\b"
                        + "|\\bsys\\s*\\.\\s*(?:objects|tables|columns|databases)\\b|\\bsysobjects\\b|\\bmysql\\s*\\.\\s*user\\b"
                        + "|\\bsqlite_master\\b|\\ball_tables\\b",
                "System catalog access",
                anyOf("information_schema", "pg_", "sys", "mysql", "sqlite_master", "all_tables")));
        r.add(rule("SQLI_FILE_OR_COMMAND", Severity.HIGH, View.STRIPPED,
                "\\bcopy\\b[^;]{0,200}?\\b(?:from|to)\\s+program\\b|\\bpg_(?:read_file|read_binary_file|ls_dir|stat_file)\\s*\\("
                        + "|\\blo_(?:import|export)\\s*\\(|\\bload_file\\s*\\(|\\binto\\s+(?:out|dump)file\\b"
                        + "|\\bdblink(?:_exec|_connect)?\\s*\\(|\\butl_(?:http|inaddr|file)\\b",
                "File read/write or OS command through the database",
                anyOf("program", "pg_", "lo_", "load_file", "outfile", "dumpfile", "dblink", "utl_")));
        r.add(rule("SQLI_CURRENT_CONTEXT", Severity.LOW, View.STRIPPED,
                "\\b(?:current_user|session_user|current_database\\s*\\(|current_setting\\s*\\(|database\\s*\\(\\s*\\))",
                "Database context function",
                anyOf("current_", "session_user", "database")));
        return r;
    }

    private static Rule rule(String id, Severity s, View v, String regex, String description, String[]... required) {
        return new Rule(id, C, s, v, regex, description, required);
    }
}

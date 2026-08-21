package com.omnicybersecurity.authcheck.auth;

import com.omnicybersecurity.authcheck.util.Text;
import org.codehaus.groovy.ast.ModuleNode;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ClosureExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.ListExpression;
import org.codehaus.groovy.ast.expr.MapEntryExpression;
import org.codehaus.groovy.ast.expr.MapExpression;
import org.codehaus.groovy.ast.expr.MethodCallExpression;
import org.codehaus.groovy.ast.expr.PropertyExpression;
import org.codehaus.groovy.ast.expr.TupleExpression;
import org.codehaus.groovy.ast.expr.VariableExpression;
import org.codehaus.groovy.ast.stmt.BlockStatement;
import org.codehaus.groovy.ast.stmt.ExpressionStatement;
import org.codehaus.groovy.ast.stmt.Statement;
import org.codehaus.groovy.control.CompilationUnit;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.Phases;
import org.codehaus.groovy.syntax.Types;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reads a script's {@code params} block out of its source without running it.
 *
 * <p>The source is parsed only as far as {@link Phases#CONVERSION}, so nothing
 * in the script executes and nothing has to resolve -- the declaration is read
 * off the syntax tree. That matters: the whole point is to know what a script
 * needs <em>before</em> anyone hands it credentials, and a login script is the
 * last thing that should run speculatively to answer a question about a form.
 *
 * <p>Because it is a syntax tree and not an evaluation, every value has to be a
 * literal. A name built at runtime is rejected rather than guessed at.
 */
public final class ScriptParamExtractor {

    /** Options a declaration may carry; anything else is a typo worth reporting. */
    private static final Set<String> KNOWN_OPTIONS = Set.of(
            "name", "label", "type", "required", "default", "defaultValue", "help", "choices");

    private static final int MAX_CACHED = 32;

    /** Parsing is not free and the UI re-derives on every pause in typing. */
    private static final Map<String, ScriptParams> CACHE = new ConcurrentHashMap<>();

    private ScriptParamExtractor() {
    }

    public static ScriptParams extract(String source) {
        if (Text.isBlank(source)) {
            return ScriptParams.none();
        }
        ScriptParams cached = CACHE.get(source);
        if (cached != null) {
            return cached;
        }
        ScriptParams extracted = parse(source);
        if (CACHE.size() >= MAX_CACHED) {
            CACHE.clear();
        }
        CACHE.put(source, extracted);
        return extracted;
    }

    private static ScriptParams parse(String source) {
        ModuleNode module;
        try {
            CompilationUnit unit = new CompilationUnit(new CompilerConfiguration());
            unit.addSource("AuthScriptParams.groovy", source);
            unit.compile(Phases.CONVERSION);
            List<ModuleNode> modules = unit.getAST().getModules();
            module = modules.isEmpty() ? null : modules.get(0);
        } catch (Exception e) {
            // A script that will not parse has a syntax error to fix first, and
            // "Check syntax" says so properly. Nothing to declare until then.
            return ScriptParams.none();
        }
        if (module == null) {
            return ScriptParams.none();
        }

        List<ScriptParam> params = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        boolean declared = false;

        for (Statement statement : module.getStatementBlock().getStatements()) {
            MethodCallExpression call = callTo(statement, "params");
            if (call == null) {
                continue;
            }
            ClosureExpression body = closureArgument(call);
            if (body == null) {
                problems.add("params needs a block: params { param 'username', required: true }");
                continue;
            }
            declared = true;
            readDeclarations(body, params, problems, seen);
        }

        return declared ? new ScriptParams(true, params, problems) : ScriptParams.none();
    }

    private static void readDeclarations(ClosureExpression body, List<ScriptParam> params,
            List<String> problems, Set<String> seen) {
        for (Statement statement : statementsOf(body)) {
            MethodCallExpression call = callTo(statement, "param");
            if (call == null) {
                problems.add(at(statement) + "only 'param' declarations belong inside params { }");
                continue;
            }
            ScriptParam param = readDeclaration(call, problems, seen);
            if (param != null) {
                params.add(param);
            }
        }
    }

    private static ScriptParam readDeclaration(MethodCallExpression call, List<String> problems,
            Set<String> seen) {
        String where = at(call);
        Map<String, Expression> options = new LinkedHashMap<>();
        String positionalName = null;

        for (Expression argument : argumentsOf(call)) {
            if (argument instanceof MapExpression map) {
                for (MapEntryExpression entry : map.getMapEntryExpressions()) {
                    String key = constantText(entry.getKeyExpression());
                    if (key == null) {
                        problems.add(where + "option names must be plain words");
                        continue;
                    }
                    if (!KNOWN_OPTIONS.contains(key)) {
                        problems.add(where + "unknown option '" + key + "'; use "
                                + String.join(", ", new java.util.TreeSet<>(KNOWN_OPTIONS)));
                        continue;
                    }
                    options.put(key, entry.getValueExpression());
                }
            } else if (positionalName == null && constantText(argument) != null) {
                positionalName = constantText(argument);
            } else {
                problems.add(where + "a param takes a literal name and options, e.g. "
                        + "param 'username', label: 'Username', required: true");
            }
        }

        String name = positionalName != null ? positionalName : constantText(options.get("name"));
        if (Text.isBlank(name)) {
            problems.add(where + "a param needs a literal name, e.g. param 'username'");
            return null;
        }
        name = name.trim();
        if (!seen.add(name)) {
            problems.add(where + "'" + name + "' is declared more than once");
            return null;
        }

        List<String> choices = stringList(options.get("choices"));
        if (options.containsKey("choices") && choices.isEmpty()) {
            problems.add(where + "'" + name + "' has choices that are not a list of literal strings");
        }

        ScriptParam.Type type = null;
        if (options.containsKey("type")) {
            String declaredType = typeText(options.get("type"));
            type = ScriptParam.Type.parse(declaredType);
            if (type == null) {
                problems.add(where + "'" + name + "' has an unknown type '"
                        + (declaredType == null ? "?" : declaredType) + "'; use one of "
                        + ScriptParam.Type.names());
                return null;
            }
        } else if (!choices.isEmpty()) {
            // Listing the permitted values is unambiguous about what is wanted.
            type = ScriptParam.Type.CHOICE;
        }

        boolean required = Boolean.TRUE.equals(constantBoolean(options.get("required")));
        if (options.containsKey("required") && constantBoolean(options.get("required")) == null) {
            problems.add(where + "'" + name + "' has a required: that is not true or false");
        }

        Expression defaultExpression = options.containsKey("default")
                ? options.get("default") : options.get("defaultValue");
        String defaultValue = constantText(defaultExpression);
        if (defaultExpression != null && defaultValue == null) {
            problems.add(where + "'" + name + "' has a default that is not a literal value");
        }

        if (required && !Text.isBlank(defaultValue)) {
            // Not a nitpick: one of the two is a lie about the field, and which
            // one the author meant is not recoverable from here.
            problems.add(where + "'" + name + "' is required and also has a default; "
                    + "a default makes a param optional, so drop one of them");
        }

        ScriptParam param = new ScriptParam(name, constantText(options.get("label")), type, required,
                defaultValue, constantText(options.get("help")), choices);

        if (param.type() == ScriptParam.Type.CHOICE && param.choices().isEmpty()) {
            problems.add(where + "'" + name + "' is a CHOICE with no choices: "
                    + "add choices: ['one', 'two']");
        }
        String defaultProblem = param.problemWith(param.defaultValue());
        if (defaultProblem != null) {
            problems.add(where + "the default for '" + name + "' " + defaultProblem);
        }
        return param;
    }

    // -- syntax tree helpers -------------------------------------------------

    private static MethodCallExpression callTo(Statement statement, String method) {
        if (!(statement instanceof ExpressionStatement expression)) {
            return null;
        }
        if (!(expression.getExpression() instanceof MethodCallExpression call)) {
            return null;
        }
        return method.equals(call.getMethodAsString()) ? call : null;
    }

    private static ClosureExpression closureArgument(MethodCallExpression call) {
        for (Expression argument : argumentsOf(call)) {
            if (argument instanceof ClosureExpression closure) {
                return closure;
            }
        }
        return null;
    }

    private static List<Expression> argumentsOf(MethodCallExpression call) {
        return call.getArguments() instanceof TupleExpression tuple
                ? tuple.getExpressions() : List.of(call.getArguments());
    }

    private static List<Statement> statementsOf(ClosureExpression closure) {
        Statement code = closure.getCode();
        if (code instanceof BlockStatement block) {
            return block.getStatements();
        }
        return code == null ? List.of() : List.of(code);
    }

    /**
     * The text of a literal, or null when the expression is anything else.
     *
     * <p>Literals joined with {@code +} count: a line of help worth writing is
     * usually longer than a line of code should be, and silently dropping the
     * half after the operator would be the worst of both.
     */
    private static String constantText(Expression expression) {
        if (expression instanceof ConstantExpression constant && constant.getValue() != null) {
            return String.valueOf(constant.getValue());
        }
        if (expression instanceof BinaryExpression binary
                && binary.getOperation().getType() == Types.PLUS) {
            String left = constantText(binary.getLeftExpression());
            String right = constantText(binary.getRightExpression());
            return left == null || right == null ? null : left + right;
        }
        return null;
    }

    private static Boolean constantBoolean(Expression expression) {
        if (expression instanceof ConstantExpression constant) {
            if (constant.getValue() instanceof Boolean value) {
                return value;
            }
            String text = constantText(expression);
            if ("true".equalsIgnoreCase(text) || "false".equalsIgnoreCase(text)) {
                return Boolean.valueOf(text);
            }
        }
        return null;
    }

    /**
     * A type is written as a bare word ({@code type: SECRET}), which is a
     * variable at this stage, or as a string, or qualified.
     */
    private static String typeText(Expression expression) {
        if (expression instanceof VariableExpression variable) {
            return variable.getName();
        }
        if (expression instanceof PropertyExpression property) {
            return property.getPropertyAsString();
        }
        return constantText(expression);
    }

    private static List<String> stringList(Expression expression) {
        List<String> values = new ArrayList<>();
        if (expression instanceof ListExpression list) {
            for (Expression element : list.getExpressions()) {
                String text = constantText(element);
                if (text == null) {
                    return List.of();
                }
                values.add(text);
            }
        }
        return values;
    }

    private static String at(Object node) {
        int line = node instanceof Statement statement ? statement.getLineNumber()
                : node instanceof Expression expression ? expression.getLineNumber() : -1;
        return line > 0 ? "line " + line + ": " : "";
    }
}

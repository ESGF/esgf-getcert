package esg.security.myproxy;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Estani
 * Simple encapsulation for console arguments handling.
 */
public class Arguments {
    
    /**
     * Thrown in case an error occur while parsing arguments.
     *
     */
    public static class InvalidArgumentException extends Exception {
        private static final long serialVersionUID = -5175065369558044873L;
        
        public InvalidArgumentException(String arg0) {super(arg0);}
    }

    private Map<String, Argument> optionsMap   = new HashMap<String, Arguments.Argument>();
    private List<Argument>        options      = new LinkedList<Arguments.Argument>();
    private List<Argument>        posArguments = new LinkedList<Arguments.Argument>();

    /**
     * @author Estani
     * Encapsulates an argument (both an option or a positional argument)
     */
    public static class Argument {
        private static int     lastArg = 0;

        private final String   shortHelp;   //help to be displayed
        private final String[] flags;       //optional flags for the same functionality
        private final String[] env;         //envirn. default value
        private final boolean  hasValue;    //if option takes value
        private String         value;       //value retrieved whe parsing option
        private final int      position;    //position of positional argument
        private boolean        optional;    //if positional argumen is optional
        
        private final String   allFlags;    //original string with multiple flags (comma separated)

        /**
         * @param names
         *            comma separated string containing the argument/option
         *            names. In this constructor call Options start with a dash
         *            arguments don't.
         * @param shortHelp
         *            a short description of the argument. The first sentence
         *            might be used for a summary much like what javadoc does,
         *            so it should me meaningful.
         * @param option
         *            In case of an option, if it expects a value. In case of an
         *            argument, if it's optional.
         * @param env
         *            Name of a java property or an environment variable from
         *            which a default value will be read.
         */
        private Argument(String names, String shortHelp, boolean option, String[] env) {
            this.shortHelp = shortHelp;
            this.env = env;
            
            // options start with dash arguments don't (does not implemente the
            // "--" flag at the moment
            if (names.charAt(0) == '-') {
                // this is an option
                this.optional = true;
                this.hasValue = option;
                this.flags = names.split(",");
                this.allFlags = names;
                this.position = -1;
            } else {
                // this is a positional argument
                this.hasValue = false;
                this.optional = option;
                this.flags = new String[] { names };
                this.allFlags = names;
                this.position = lastArg++;
            }
        }

        /**
         * @return the value parsed or the default value from the java property
         *         or environment variable defined at creation time.
         */
        public String getValue() {
            if (value == null) {
                //check all possible default values
                for (int i = 0; i < env.length; i++) {
                    if (System.getProperty(env[i]) != null) return System.getProperty(env[i]);
                    if (System.getenv(env[i]) != null) return System.getenv(env[i]);
                }
            }
            return value;
        }
        

        /**
         * @return the position
         */
        public int getPosition() {
            return position;
        }

        /**
         * @return if it is optional
         */
        public boolean isOptional() {
            return optional;
        }

        /**
         * @param args array of arguments to be parsed
         * @param width wrap width (def:80)
         * @return A String showing the arguments wrapped to the given width
         */
        public static String format(Argument[] args, int... width) {
            StringBuilder sb = new StringBuilder();
            int size = (width.length == 0 ? 80 : width[0]);

            int flags = 0;
//            boolean hasVal = false;

            for (Argument a : args) {
                if (a.flags != null && a.allFlags.length() > flags) flags = a.allFlags
                        .length();
//                hasVal |= a.hasValue;
            }

            //-6 represents "<val> " or the empty space
            int descSize = size - flags - 6;

            for (int i = 0; i < args.length; i++) {
                sb.append(String.format("%-" + flags + "s "
                        + (args[i].hasValue ? "<val> " : "      "),
                args[i].allFlags));

                // wrap shortHelp (
                wrap(args[i].shortHelp, descSize, String.format("%"
                        + (size - descSize - 2) + "s", " "), sb);
            }
            return sb.toString();
        }

        private static void wrap(String line, int width, String indent,
                StringBuilder sb) {
            if (line.length() <= width) {
                // no wrapping
                sb.append(line).append('\n');
                return;
            }
            boolean first = true;
            int start = 0;

            for (int end = width; end > start; end--) {
                if (line.charAt(end) == ' ') {
                    // split
                    if (first) first = false;
                    else sb.append(indent);
                    sb.append(line.substring(start, end)).append('\n');
                    start = end + 1;
                    end += width;
                    if (end >= line.length()) {
                        sb.append(indent);
                        sb.append(line.substring(start)).append('\n');
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * Creates a simple argument.
     * @param flags
     *            comma separated list of options that must start with one or
     *            two dashes
     * @param shortDesc
     *            brief explanation
     * @return The created argument
     */
    public Argument setOption(String flags, String shortDesc) {
        return setOption(flags, shortDesc, false);
    }

    /**
     * Creates an argument.
     * @param flags
     *            comma separated list of options that must start with one or
     *            two dashes
     * @param shortDesc
     *            brief explanation
     * @param hasValue
     *            if the option takes a value
     * @param envVal
     *            Environmental variables (or java properties) which represents
     *            the argument default value. Might be more than one, the first
     *            non empty one is returned.
     * @return The created argument
     */
    public Argument setOption(String flags, String shortDesc, boolean hasValue, String... envVal) {
        Argument arg = new Argument(flags, shortDesc, hasValue, envVal);
        for (String s : arg.flags) {
            // save one link per flag
            optionsMap.put(s, arg);
        }
        options.add(arg);
        return arg;
    }

    /**
     * @param name
     *            argument name
     * @param shortDesc
     *            description
     * @param optional
     *            if this arument is required
     * @param envVal
     *            Environmental variables (or java properties) which represents
     *            the argument default value. Might be more than one, the first
     *            non empty one is returned.
     * @return the created argument
     */
    public Argument setArgument(String name, String shortDesc, boolean optional, String... envVal) {
        Argument arg = new Argument(name, shortDesc, optional, envVal);
        // no flag implies this is a positional argument
        posArguments.add(arg);
        return arg;
    }

    /**
     * Parses a String array according to the currently setup arguments.
     * @param args arguments to be parsed
     * @return the list of parsed arguments. These are the arguments found in the calling.
     * @throws InvalidArgumentException if the arguments could not be parsed
     */
    public List<Argument> parseArguments(String[] args)
            throws InvalidArgumentException {
        List<Argument> parsedArgs = new LinkedList<Argument>();
        for (int i = 0; i < args.length; i++) {
            String opt = args[i];
            if (opt.length() == 0) continue;
            if (opt.charAt(0) == '-' && opt.charAt(1) != '-' && opt.length() > 2) {
                //multiple options!
                opt = opt.substring(0,2);
                args[i] = "-" + args[i].substring(2);
                i--;
            }
            Argument arg = optionsMap.get(opt);
            if (arg == null) throw new InvalidArgumentException(opt
                    + " is not a valid argument.");
            else {
                if (arg.hasValue) {
                    i++;
                    if (args.length <= i || args[i].charAt(0) == '-') throw new InvalidArgumentException(
                            "Mising operand for argument " + opt);
                    arg.value = args[i];
                }
                parsedArgs.add(arg);
            }
        }
        return parsedArgs;
    }

    /**
     * Displays info on all arguments as a sort of help. 
     * @param message message to be displayed as header.
     */
    public void showUsage(String message) {
        System.out.println(getUsage(message));
    }

    /**
     * @param message
     *            message to be displayed as header.
     * @return A string containing the given header and the list of arguments
     *         ready to be displayed as the command usage.
     */
    public String getUsage(String message, int... width) {
        StringBuilder sb = new StringBuilder();
        if (message != null) {
            if (width.length > 0) Argument.wrap(message, width[0], "", sb);
            else sb.append(message).append('\n');
        }
        
        // arguments
        sb.append(Argument.format(posArguments
                .toArray(new Argument[posArguments.size()]), width));
        // options
        sb.append(Argument
                .format(options.toArray(new Argument[options.size()]), width));
        
        return sb.toString();
    }
}

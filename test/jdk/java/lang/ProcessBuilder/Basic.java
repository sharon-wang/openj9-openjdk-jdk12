/*
 * Copyright (c) 2003, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 4199068 4738465 4937983 4930681 4926230 4931433 4932663 4986689
 *      5026830 5023243 5070673 4052517 4811767 6192449 6397034 6413313
 *      6464154 6523983 6206031 4960438 6631352 6631966 6850957 6850958
 *      4947220 7018606 7034570 4244896 5049299 8003488 8054494 8058464
 *      8067796
 * @key intermittent
 * @summary Basic tests for Process and Environment Variable code
 * @modules java.base/java.lang:open
 * @run main/othervm/timeout=300 Basic
 * @run main/othervm/timeout=300 -Djdk.lang.Process.launchMechanism=fork Basic
 * @author Martin Buchholz
 */

/*
 * @test
 * @modules java.base/java.lang:open
 * @requires (os.family == "linux")
 * @run main/othervm/timeout=300 -Djdk.lang.Process.launchMechanism=posix_spawn Basic
 */

import java.lang.ProcessBuilder.Redirect;
import java.lang.ProcessHandle;
import static java.lang.ProcessBuilder.Redirect.*;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.security.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import static java.lang.System.getenv;
import static java.lang.System.out;
import static java.lang.Boolean.TRUE;
import static java.util.AbstractMap.SimpleImmutableEntry;

public class Basic {

    /* used for Windows only */
    static final String systemRoot = System.getenv("SystemRoot");

    /* used for Mac OS X only */
    static final String cfUserTextEncoding = System.getenv("__CF_USER_TEXT_ENCODING");

    /* used for AIX only */
    static final String libpath = System.getenv("LIBPATH");

    /**
     * Returns the number of milliseconds since time given by
     * startNanoTime, which must have been previously returned from a
     * call to {@link System.nanoTime()}.
     */
    private static long millisElapsedSince(long startNanoTime) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanoTime);
    }

    private static String commandOutput(Reader r) throws Throwable {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = r.read()) > 0)
            if (c != '\r')
                sb.append((char) c);
        return sb.toString();
    }

    private static String commandOutput(Process p) throws Throwable {
        check(p.getInputStream()  == p.getInputStream());
        check(p.getOutputStream() == p.getOutputStream());
        check(p.getErrorStream()  == p.getErrorStream());
        Reader r = new InputStreamReader(p.getInputStream(),"UTF-8");
        String output = commandOutput(r);
        equal(p.waitFor(), 0);
        equal(p.exitValue(), 0);
        // The debug/fastdebug versions of the VM may write some warnings to stdout
        // (i.e. "Warning:  Cannot open log file: hotspot.log" if the VM is started
        // in a directory without write permissions). These warnings will confuse tests
        // which match the entire output of the child process so better filter them out.
        return output.replaceAll("Warning:.*\\n", "");
    }

    private static String commandOutput(ProcessBuilder pb) {
        try {
            return commandOutput(pb.start());
        } catch (Throwable t) {
            String commandline = "";
            for (String arg : pb.command())
                commandline += " " + arg;
            System.out.println("Exception trying to run process: " + commandline);
            unexpected(t);
            return "";
        }
    }

    private static String commandOutput(String...command) {
        try {
            return commandOutput(Runtime.getRuntime().exec(command));
        } catch (Throwable t) {
            String commandline = "";
            for (String arg : command)
                commandline += " " + arg;
            System.out.println("Exception trying to run process: " + commandline);
            unexpected(t);
            return "";
        }
    }

    private static void checkCommandOutput(ProcessBuilder pb,
                                           String expected,
                                           String failureMsg) {
        String got = commandOutput(pb);
        check(got.equals(expected),
              failureMsg + "\n" +
              "Expected: \"" + expected + "\"\n" +
              "Got: \"" + got + "\"");
    }

    private static String absolutifyPath(String path) {
        StringBuilder sb = new StringBuilder();
        for (String file : path.split(File.pathSeparator)) {
            if (sb.length() != 0)
                sb.append(File.pathSeparator);
            sb.append(new File(file).getAbsolutePath());
        }
        return sb.toString();
    }

    // compare windows-style, by canonicalizing to upper case,
    // not lower case as String.compareToIgnoreCase does
    private static class WindowsComparator
        implements Comparator<String> {
        public int compare(String x, String y) {
            return x.toUpperCase(Locale.US)
                .compareTo(y.toUpperCase(Locale.US));
        }
    }

    private static String sortedLines(String lines) {
        String[] arr = lines.split("\n");
        List<String> ls = new ArrayList<String>();
        for (String s : arr)
            ls.add(s);
        Collections.sort(ls, new WindowsComparator());
        StringBuilder sb = new StringBuilder();
        for (String s : ls)
            sb.append(s + "\n");
        return sb.toString();
    }

    private static void compareLinesIgnoreCase(String lines1, String lines2) {
        if (! (sortedLines(lines1).equalsIgnoreCase(sortedLines(lines2)))) {
            String dashes =
                "-----------------------------------------------------";
            out.println(dashes);
            out.print(sortedLines(lines1));
            out.println(dashes);
            out.print(sortedLines(lines2));
            out.println(dashes);
            out.println("sizes: " + sortedLines(lines1).length() +
                        " " + sortedLines(lines2).length());

            fail("Sorted string contents differ");
        }
    }

    private static final Runtime runtime = Runtime.getRuntime();

    private static final String[] winEnvCommand = {"cmd.exe", "/c", "set"};

    private static String winEnvFilter(String env) {
        return env.replaceAll("\r", "")
            .replaceAll("(?m)^(?:COMSPEC|PROMPT|PATHEXT)=.*\n","");
    }

    private static String unixEnvProg() {
        return new File("/usr/bin/env").canExecute() ? "/usr/bin/env"
            : "/bin/env";
    }

    private static String nativeEnv(String[] env) {
        try {
            if (Windows.is()) {
                return winEnvFilter
                    (commandOutput(runtime.exec(winEnvCommand, env)));
            } else {
                return commandOutput(runtime.exec(unixEnvProg(), env));
            }
        } catch (Throwable t) { throw new Error(t); }
    }

    private static String nativeEnv(ProcessBuilder pb) {
        try {
            if (Windows.is()) {
                pb.command(winEnvCommand);
                return winEnvFilter(commandOutput(pb));
            } else {
                pb.command(new String[]{unixEnvProg()});
                return commandOutput(pb);
            }
        } catch (Throwable t) { throw new Error(t); }
    }

    private static void checkSizes(Map<String,String> environ, int size) {
        try {
            equal(size, environ.size());
            equal(size, environ.entrySet().size());
            equal(size, environ.keySet().size());
            equal(size, environ.values().size());

            boolean isEmpty = (size == 0);
            equal(isEmpty, environ.isEmpty());
            equal(isEmpty, environ.entrySet().isEmpty());
            equal(isEmpty, environ.keySet().isEmpty());
            equal(isEmpty, environ.values().isEmpty());
        } catch (Throwable t) { unexpected(t); }
    }

    private interface EnvironmentFrobber {
        void doIt(Map<String,String> environ);
    }

    private static void testVariableDeleter(EnvironmentFrobber fooDeleter) {
        try {
            Map<String,String> environ = new ProcessBuilder().environment();
            environ.put("Foo", "BAAR");
            fooDeleter.doIt(environ);
            equal(environ.get("Foo"), null);
            equal(environ.remove("Foo"), null);
        } catch (Throwable t) { unexpected(t); }
    }

    private static void testVariableAdder(EnvironmentFrobber fooAdder) {
        try {
            Map<String,String> environ = new ProcessBuilder().environment();
            environ.remove("Foo");
            fooAdder.doIt(environ);
            equal(environ.get("Foo"), "Bahrein");
        } catch (Throwable t) { unexpected(t); }
    }

    private static void testVariableModifier(EnvironmentFrobber fooModifier) {
        try {
            Map<String,String> environ = new ProcessBuilder().environment();
            environ.put("Foo","OldValue");
            fooModifier.doIt(environ);
            equal(environ.get("Foo"), "NewValue");
        } catch (Throwable t) { unexpected(t); }
    }

    private static void printUTF8(String s) throws IOException {
        out.write(s.getBytes("UTF-8"));
    }

    private static String getenvAsString(Map<String,String> environment) {
        StringBuilder sb = new StringBuilder();
        environment = new TreeMap<>(environment);
        for (Map.Entry<String,String> e : environment.entrySet())
            // Ignore magic environment variables added by the launcher
            if (! e.getKey().equals("LD_LIBRARY_PATH"))
                sb.append(e.getKey())
                    .append('=')
                    .append(e.getValue())
                    .append(',');
        return sb.toString();
    }

    static void print4095(OutputStream s, byte b) throws Throwable {
        byte[] bytes = new byte[4095];
        Arrays.fill(bytes, b);
        s.write(bytes);         // Might hang!
    }

    static void checkPermissionDenied(ProcessBuilder pb) {
        try {
            pb.start();
            fail("Expected IOException not thrown");
        } catch (IOException e) {
            String m = e.getMessage();
            if (EnglishUnix.is() &&
                ! matches(m, "Permission denied"))
                unexpected(e);
        } catch (Throwable t) { unexpected(t); }
    }

    public static class JavaChild {
        public static void main(String args[]) throws Throwable {
            String action = args[0];
            if (action.equals("sleep")) {
                Thread.sleep(10 * 60 * 1000L);
            } else if (action.equals("pid")) {
                System.out.println(ProcessHandle.current().pid());
            } else if (action.equals("testIO")) {
                String expected = "standard input";
                char[] buf = new char[expected.length()+1];
                int n = new InputStreamReader(System.in).read(buf,0,buf.length);
                if (n != expected.length())
                    System.exit(5);
                if (! new String(buf,0,n).equals(expected))
                    System.exit(5);
                System.err.print("standard error");
                System.out.print("standard output");
            } else if (action.equals("testInheritIO")
                    || action.equals("testRedirectInherit")) {
                List<String> childArgs = new ArrayList<String>(javaChildArgs);
                childArgs.add("testIO");
                ProcessBuilder pb = new ProcessBuilder(childArgs);
                if (action.equals("testInheritIO"))
                    pb.inheritIO();
                else
                    redirectIO(pb, INHERIT, INHERIT, INHERIT);
                ProcessResults r = run(pb);
                if (! r.out().equals(""))
                    System.exit(7);
                if (! r.err().equals(""))
                    System.exit(8);
                if (r.exitValue() != 0)
                    System.exit(9);
            } else if (action.equals("System.getenv(String)")) {
                String val = System.getenv(args[1]);
                printUTF8(val == null ? "null" : val);
            } else if (action.equals("System.getenv(\\u1234)")) {
                String val = System.getenv("\u1234");
                printUTF8(val == null ? "null" : val);
            } else if (action.equals("System.getenv()")) {
                printUTF8(getenvAsString(System.getenv()));
            } else if (action.equals("ArrayOOME")) {
                Object dummy;
                switch(new Random().nextInt(3)) {
                case 0: dummy = new Integer[Integer.MAX_VALUE]; break;
                case 1: dummy = new double[Integer.MAX_VALUE];  break;
                case 2: dummy = new byte[Integer.MAX_VALUE][];  break;
                default: throw new InternalError();
                }
            } else if (action.equals("TestError")) {
                throw new InternalError();
            } else if (action.equals("pwd")) {
                printUTF8(new File(System.getProperty("user.dir"))
                          .getCanonicalPath());
            } else if (action.equals("print4095")) {
                print4095(System.out, (byte) '!');
                print4095(System.err, (byte) 'E');
                System.exit(5);
            } else if (action.equals("OutErr")) {
                // You might think the system streams would be
                // buffered, and in fact they are implemented using
                // BufferedOutputStream, but each and every print
                // causes immediate operating system I/O.
                System.out.print("out");
                System.err.print("err");
                System.out.print("out");
                System.err.print("err");
            } else if (action.equals("null PATH")) {
                equal(System.getenv("PATH"), null);
                check(new File("/bin/true").exists());
                check(new File("/bin/false").exists());
                ProcessBuilder pb1 = new ProcessBuilder();
                ProcessBuilder pb2 = new ProcessBuilder();
                pb2.environment().put("PATH", "anyOldPathIgnoredAnyways");
                ProcessResults r;

                for (final ProcessBuilder pb :
                         new ProcessBuilder[] {pb1, pb2}) {
                    pb.command("true");
                    equal(run(pb).exitValue(), True.exitValue());

                    pb.command("false");
                    equal(run(pb).exitValue(), False.exitValue());
                }

                if (failed != 0) throw new Error("null PATH");
            } else if (action.equals("PATH search algorithm")) {
                equal(System.getenv("PATH"), "dir1:dir2:");
                check(new File("/bin/true").exists());
                check(new File("/bin/false").exists());
                String[] cmd = {"prog"};
                ProcessBuilder pb1 = new ProcessBuilder(cmd);
                ProcessBuilder pb2 = new ProcessBuilder(cmd);
                ProcessBuilder pb3 = new ProcessBuilder(cmd);
                pb2.environment().put("PATH", "anyOldPathIgnoredAnyways");
                pb3.environment().remove("PATH");

                for (final ProcessBuilder pb :
                         new ProcessBuilder[] {pb1, pb2, pb3}) {
                    try {
                        // Not on PATH at all; directories don't exist
                        try {
                            pb.start();
                            fail("Expected IOException not thrown");
                        } catch (IOException e) {
                            String m = e.getMessage();
                            if (EnglishUnix.is() &&
                                ! matches(m, "No such file"))
                                unexpected(e);
                        } catch (Throwable t) { unexpected(t); }

                        // Not on PATH at all; directories exist
                        new File("dir1").mkdirs();
                        new File("dir2").mkdirs();
                        try {
                            pb.start();
                            fail("Expected IOException not thrown");
                        } catch (IOException e) {
                            String m = e.getMessage();
                            if (EnglishUnix.is() &&
                                ! matches(m, "No such file"))
                                unexpected(e);
                        } catch (Throwable t) { unexpected(t); }

                        // Can't execute a directory -- permission denied
                        // Report EACCES errno
                        new File("dir1/prog").mkdirs();
                        checkPermissionDenied(pb);

                        // continue searching if EACCES
                        copy("/bin/true", "dir2/prog");
                        equal(run(pb).exitValue(), True.exitValue());
                        new File("dir1/prog").delete();
                        new File("dir2/prog").delete();

                        new File("dir2/prog").mkdirs();
                        copy("/bin/true", "dir1/prog");
                        equal(run(pb).exitValue(), True.exitValue());

                        // Check empty PATH component means current directory.
                        //
                        // While we're here, let's test different kinds of
                        // Unix executables, and PATH vs explicit searching.
                        new File("dir1/prog").delete();
                        new File("dir2/prog").delete();
                        for (String[] command :
                                 new String[][] {
                                     new String[] {"./prog"},
                                     cmd}) {
                            pb.command(command);
                            File prog = new File("./prog");
                            // "Normal" binaries
                            copy("/bin/true", "./prog");
                            equal(run(pb).exitValue(),
                                  True.exitValue());
                            copy("/bin/false", "./prog");
                            equal(run(pb).exitValue(),
                                  False.exitValue());
                            prog.delete();
                            // Interpreter scripts with #!
                            setFileContents(prog, "#!/bin/true\n");
                            prog.setExecutable(true);
                            equal(run(pb).exitValue(),
                                  True.exitValue());
                            prog.delete();
                            setFileContents(prog, "#!/bin/false\n");
                            prog.setExecutable(true);
                            equal(run(pb).exitValue(),
                                  False.exitValue());
                            // Traditional shell scripts without #!
                            setFileContents(prog, "exec /bin/true\n");
                            prog.setExecutable(true);
                            equal(run(pb).exitValue(),
                                  True.exitValue());
                            prog.delete();
                            setFileContents(prog, "exec /bin/false\n");
                            prog.setExecutable(true);
                            equal(run(pb).exitValue(),
                                  False.exitValue());
                            prog.delete();
                        }

                        // Test Unix interpreter scripts
                        File dir1Prog = new File("dir1/prog");
                        dir1Prog.delete();
                        pb.command(new String[] {"prog", "world"});
                        setFileContents(dir1Prog, "#!/bin/echo hello\n");
                        checkPermissionDenied(pb);
                        dir1Prog.setExecutable(true);
                        equal(run(pb).out(), "hello dir1/prog world\n");
                        equal(run(pb).exitValue(), True.exitValue());
                        dir1Prog.delete();
                        pb.command(cmd);

                        // Test traditional shell scripts without #!
                        setFileContents(dir1Prog, "/bin/echo \"$@\"\n");
                        pb.command(new String[] {"prog", "hello", "world"});
                        checkPermissionDenied(pb);
                        dir1Prog.setExecutable(true);
                        equal(run(pb).out(), "hello world\n");
                        equal(run(pb).exitValue(), True.exitValue());
                        dir1Prog.delete();
                        pb.command(cmd);

                        // If prog found on both parent and child's PATH,
                        // parent's is used.
                        new File("dir1/prog").delete();
                        new File("dir2/prog").delete();
                        new File("prog").delete();
                        new File("dir3").mkdirs();
                        copy("/bin/true", "dir1/prog");
                        copy("/bin/false", "dir3/prog");
                        pb.environment().put("PATH","dir3");
                        equal(run(pb).exitValue(), True.exitValue());
                        copy("/bin/true", "dir3/prog");
                        copy("/bin/false", "dir1/prog");
                        equal(run(pb).exitValue(), False.exitValue());

                    } finally {
                        // cleanup
                        new File("dir1/prog").delete();
                        new File("dir2/prog").delete();
                        new File("dir3/prog").delete();
                        new File("dir1").delete();
                        new File("dir2").delete();
                        new File("dir3").delete();
                        new File("prog").delete();
                    }
                }

                if (failed != 0) throw new Error("PATH search algorithm");
            }
            else throw new Error("JavaChild invocation error");
        }
    }

    private static void copy(String src, String dst) throws IOException {
        Files.copy(Paths.get(src), Paths.get(dst),
                   StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
    }

    private static String javaChildOutput(ProcessBuilder pb, String...args) {
        List<String> list = new ArrayList<String>(javaChildArgs);
        for (String arg : args)
            list.add(arg);
        pb.command(list);
        return commandOutput(pb);
    }

    private static String getenvInChild(ProcessBuilder pb) {
        return javaChildOutput(pb, "System.getenv()");
    }

    private static String getenvInChild1234(ProcessBuilder pb) {
        return javaChildOutput(pb, "System.getenv(\\u1234)");
    }

    private static String getenvInChild(ProcessBuilder pb, String name) {
        return javaChildOutput(pb, "System.getenv(String)", name);
    }

    private static String pwdInChild(ProcessBuilder pb) {
        return javaChildOutput(pb, "pwd");
    }

    private static final String javaExe =
        System.getProperty("java.home") +
        File.separator + "bin" + File.separator + "java";

    private static final String classpath =
        System.getProperty("java.class.path");

    private static final List<String> javaChildArgs =
        Arrays.asList(javaExe,
                      "-XX:+DisplayVMOutputToStderr",
                      "-classpath", absolutifyPath(classpath),
                      "Basic$JavaChild");

    private static void testEncoding(String encoding, String tested) {
        try {
            // If round trip conversion works, should be able to set env vars
            // correctly in child.
            if (new String(tested.getBytes()).equals(tested)) {
                out.println("Testing " + encoding + " environment values");
                ProcessBuilder pb = new ProcessBuilder();
                pb.environment().put("ASCIINAME",tested);
                equal(getenvInChild(pb,"ASCIINAME"), tested);
            }
        } catch (Throwable t) { unexpected(t); }
    }

    static class Windows {
        public static boolean is() { return is; }
        private static final boolean is =
            System.getProperty("os.name").startsWith("Windows");
    }

    static class AIX {
        public static boolean is() { return is; }
        private static final boolean is =
            System.getProperty("os.name").equals("AIX");
    }

    static class Unix {
        public static boolean is() { return is; }
        private static final boolean is =
            (! Windows.is() &&
             new File("/bin/sh").exists() &&
             new File("/bin/true").exists() &&
             new File("/bin/false").exists());
    }

    static class UnicodeOS {
        public static boolean is() { return is; }
        private static final String osName = System.getProperty("os.name");
        private static final boolean is =
            // MacOS X would probably also qualify
            osName.startsWith("Windows")   &&
            ! osName.startsWith("Windows 9") &&
            ! osName.equals("Windows Me");
    }

    static class MacOSX {
        public static boolean is() { return is; }
        private static final String osName = System.getProperty("os.name");
        private static final boolean is = osName.contains("OS X");
    }

    static class True {
        public static int exitValue() { return 0; }
    }

    private static class False {
        public static int exitValue() { return exitValue; }
        private static final int exitValue = exitValue0();
        private static int exitValue0() {
            // /bin/false returns an *unspecified* non-zero number.
            try {
                if (! Unix.is())
                    return -1;
                else {
                    int rc = new ProcessBuilder("/bin/false")
                        .start().waitFor();
                    check(rc != 0);
                    return rc;
                }
            } catch (Throwable t) { unexpected(t); return -1; }
        }
    }

    static class EnglishUnix {
        private static final Boolean is =
            (! Windows.is() && isEnglish("LANG") && isEnglish("LC_ALL"));

        private static boolean isEnglish(String envvar) {
            String val = getenv(envvar);
            return (val == null) || val.matches("en.*") || val.matches("C");
        }

        /** Returns true if we can expect English OS error strings */
        static boolean is() { return is; }
    }

    static class DelegatingProcess extends Process {
        final Process p;

        DelegatingProcess(Process p) {
            this.p = p;
        }

        @Override
        public void destroy() {
            p.destroy();
        }

        @Override
        public int exitValue() {
            return p.exitValue();
        }

        @Override
        public int waitFor() throws InterruptedException {
            return p.waitFor();
        }

        @Override
        public OutputStream getOutputStream() {
            return p.getOutputStream();
        }

        @Override
        public InputStream getInputStream() {
            return p.getInputStream();
        }

        @Override
        public InputStream getErrorStream() {
            return p.getErrorStream();
        }
    }

    private static boolean matches(String str, String regex) {
        return Pattern.compile(regex).matcher(str).find();
    }

    private static String matchAndExtract(String str, String regex) {
        Matcher matcher = Pattern.compile(regex).matcher(str);
        if (matcher.find()) {
            return matcher.group();
        } else {
            return "";
        }
    }

    /* Only used for Mac OS X --
     * Mac OS X (may) add the variable __CF_USER_TEXT_ENCODING to an empty
     * environment. The environment variable JAVA_MAIN_CLASS_<pid> may also
     * be set in Mac OS X.
     * Remove them both from the list of env variables
     */
    private static String removeMacExpectedVars(String vars) {
        // Check for __CF_USER_TEXT_ENCODING
        String cleanedVars = vars.replace("__CF_USER_TEXT_ENCODING="
                                            +cfUserTextEncoding+",","");
        // Check for JAVA_MAIN_CLASS_<pid>
        String javaMainClassStr
                = matchAndExtract(cleanedVars,
                                    "JAVA_MAIN_CLASS_\\d+=Basic.JavaChild,");
        return cleanedVars.replace(javaMainClassStr,"");
    }

    /* Only used for AIX --
     * AIX adds the variable AIXTHREAD_GUARDPAGES=0 to the environment.
     * Remove it from the list of env variables
     */
    private static String removeAixExpectedVars(String vars) {
        return vars.replace("AIXTHREAD_GUARDPAGES=0,", "");
    }

    private static String sortByLinesWindowsly(String text) {
        String[] lines = text.split("\n");
        Arrays.sort(lines, new WindowsComparator());
        StringBuilder sb = new StringBuilder();
        for (String line : lines)
            sb.append(line).append("\n");
        return sb.toString();
    }

    private static void checkMapSanity(Map<String,String> map) {
        try {
            Set<String> keySet = map.keySet();
            Collection<String> values = map.values();
            Set<Map.Entry<String,String>> entrySet = map.entrySet();

            equal(entrySet.size(), keySet.size());
            equal(entrySet.size(), values.size());

            StringBuilder s1 = new StringBuilder();
            for (Map.Entry<String,String> e : entrySet)
                s1.append(e.getKey() + "=" + e.getValue() + "\n");

            StringBuilder s2 = new StringBuilder();
            for (String var : keySet)
                s2.append(var + "=" + map.get(var) + "\n");

            equal(s1.toString(), s2.toString());

            Iterator<String> kIter = keySet.iterator();
            Iterator<String> vIter = values.iterator();
            Iterator<Map.Entry<String,String>> eIter = entrySet.iterator();

            while (eIter.hasNext()) {
                Map.Entry<String,String> entry = eIter.next();
                String key   = kIter.next();
                String value = vIter.next();
                check(entrySet.contains(entry));
                check(keySet.contains(key));
                check(values.contains(value));
                check(map.containsKey(key));
                check(map.containsValue(value));
                equal(entry.getKey(), key);
                equal(entry.getValue(), value);
            }
            check(!kIter.hasNext() &&
                    !vIter.hasNext());

        } catch (Throwable t) { unexpected(t); }
    }

    private static void checkMapEquality(Map<String,String> map1,
                                         Map<String,String> map2) {
        try {
            equal(map1.size(), map2.size());
            equal(map1.isEmpty(), map2.isEmpty());
            for (String key : map1.keySet()) {
                equal(map1.get(key), map2.get(key));
                check(map2.keySet().contains(key));
            }
            equal(map1, map2);
            equal(map2, map1);
            equal(map1.entrySet(), map2.entrySet());
            equal(map2.entrySet(), map1.entrySet());
            equal(map1.keySet(), map2.keySet());
            equal(map2.keySet(), map1.keySet());

            equal(map1.hashCode(), map2.hashCode());
            equal(map1.entrySet().hashCode(), map2.entrySet().hashCode());
            equal(map1.keySet().hashCode(), map2.keySet().hashCode());
        } catch (Throwable t) { unexpected(t); }
    }

    static void checkRedirects(ProcessBuilder pb,
                               Redirect in, Redirect out, Redirect err) {
        equal(pb.redirectInput(), in);
        equal(pb.redirectOutput(), out);
        equal(pb.redirectError(), err);
    }

    static void redirectIO(ProcessBuilder pb,
                           Redirect in, Redirect out, Redirect err) {
        pb.redirectInput(in);
        pb.redirectOutput(out);
        pb.redirectError(err);
    }

    static void setFileContents(File file, String contents) {
        try {
            Writer w = new FileWriter(file);
            w.write(contents);
            w.close();
        } catch (Throwable t) { unexpected(t); }
    }

    static String fileContents(File file) {
        try {
            Reader r = new FileReader(file);
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[1024];
            int n;
            while ((n = r.read(buffer)) != -1)
                sb.append(buffer,0,n);
            r.close();
            return new String(sb);
        } catch (Throwable t) { unexpected(t); return ""; }
    }

    static void checkProcessPid() {
        ProcessBuilder pb = new ProcessBuilder();
        List<String> list = new ArrayList<String>(javaChildArgs);
        list.add("pid");
        pb.command(list);
        try {
            Process p = pb.start();
            String s = commandOutput(p);
            long actualPid = Long.valueOf(s.trim());
            long expectedPid = p.pid();
            equal(actualPid, expectedPid);
        } catch (Throwable t) {
            unexpected(t);
        }


        // Test the default implementation of Process.getPid
        DelegatingProcess p = new DelegatingProcess(null);
        THROWS(UnsupportedOperationException.class,
                () -> p.pid(),
                () -> p.toHandle(),
                () -> p.supportsNormalTermination(),
                () -> p.children(),
                () -> p.descendants());

    }

    private static void realMain(String[] args) throws Throwable {
        if (Windows.is())
            System.out.println("This appears to be a Windows system.");
        if (Unix.is())
            System.out.println("This appears to be a Unix system.");
        if (UnicodeOS.is())
            System.out.println("This appears to be a Unicode-based OS.");

        String testID = "*** TEST IDENTIFIER ***";

        //----------------------------------------------------------------
        // OOME in child allocating maximally sized array
        // Test for hotspot/jvmti bug 6850957
        //----------------------------------------------------------------
        try {
            List<String> list = new ArrayList<String>(javaChildArgs);
            list.add(1, String.format("-XX:OnOutOfMemoryError=%s -version",
                                      javaExe));
            list.add("ArrayOOME");

            out.println(testID + "command list:\n" + Arrays.toString(list.toArray()));

            ProcessResults r = run(new ProcessBuilder(list));
            out.println(testID + " - process results ERROR: \n" + r.err() + "\n ********\n");
            out.println(testID + " - process results OUT: " + r.out( )+ "\n ********\n");
            check(r.err().contains("java.lang.OutOfMemoryError:"));
            check(r.err().contains(javaExe));
            check(r.err().contains(System.getProperty("java.version")));     
            equal(r.exitValue(), 1);
        } catch (Throwable t) { unexpected(t); }
    }

    static void closeStreams(Process p) {
        try {
            p.getOutputStream().close();
            p.getInputStream().close();
            p.getErrorStream().close();
        } catch (Throwable t) { unexpected(t); }
    }

    //----------------------------------------------------------------
    // A Policy class designed to make permissions fiddling very easy.
    //----------------------------------------------------------------
    private static class Policy extends java.security.Policy {
        private Permissions perms;

        public void setPermissions(Permission...permissions) {
            perms = new Permissions();
            for (Permission permission : permissions)
                perms.add(permission);
        }

        public Policy() { setPermissions(/* Nothing */); }

        public PermissionCollection getPermissions(CodeSource cs) {
            return perms;
        }

        public PermissionCollection getPermissions(ProtectionDomain pd) {
            return perms;
        }

        public boolean implies(ProtectionDomain pd, Permission p) {
            return perms.implies(p);
        }

        public void refresh() {}
    }

    private static class StreamAccumulator extends Thread {
        private final InputStream is;
        private final StringBuilder sb = new StringBuilder();
        private Throwable throwable = null;

        public String result () throws Throwable {
            if (throwable != null)
                throw throwable;
            return sb.toString();
        }

        StreamAccumulator (InputStream is) {
            this.is = is;
        }

        public void run() {
            try {
                Reader r = new InputStreamReader(is);
                char[] buf = new char[4096];
                int n;
                while ((n = r.read(buf)) > 0) {
                    sb.append(buf,0,n);
                }
            } catch (Throwable t) {
                throwable = t;
            } finally {
                try { is.close(); }
                catch (Throwable t) { throwable = t; }
            }
        }
    }

    static ProcessResults run(ProcessBuilder pb) {
        try {
            return run(pb.start());
        } catch (Throwable t) { unexpected(t); return null; }
    }

    private static ProcessResults run(Process p) {
        Throwable throwable = null;
        int exitValue = -1;
        String out = "";
        String err = "";

        StreamAccumulator outAccumulator =
            new StreamAccumulator(p.getInputStream());
        StreamAccumulator errAccumulator =
            new StreamAccumulator(p.getErrorStream());

        try {
            outAccumulator.start();
            errAccumulator.start();

            exitValue = p.waitFor();

            outAccumulator.join();
            errAccumulator.join();

            out = outAccumulator.result();
            err = errAccumulator.result();
        } catch (Throwable t) {
            throwable = t;
        }
        return new ProcessResults(out, err, exitValue, throwable);
    }

    //----------------------------------------------------------------
    // Results of a command
    //----------------------------------------------------------------
    private static class ProcessResults {
        private final String out;
        private final String err;
        private final int exitValue;
        private final Throwable throwable;

        public ProcessResults(String out,
                              String err,
                              int exitValue,
                              Throwable throwable) {
            this.out = out;
            this.err = err;
            this.exitValue = exitValue;
            this.throwable = throwable;
        }

        public String out()          { return out; }
        public String err()          { return err; }
        public int exitValue()       { return exitValue; }
        public Throwable throwable() { return throwable; }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("<STDOUT>\n" + out() + "</STDOUT>\n")
                .append("<STDERR>\n" + err() + "</STDERR>\n")
                .append("exitValue = " + exitValue + "\n");
            if (throwable != null)
                sb.append(throwable.getStackTrace());
            return sb.toString();
        }
    }

    //--------------------- Infrastructure ---------------------------
    static volatile int passed = 0, failed = 0;
    static void pass() {passed++;}
    static void fail() {failed++; Thread.dumpStack();}
    static void fail(String msg) {System.err.println(msg); fail();}
    static void unexpected(Throwable t) {failed++; t.printStackTrace();}
    static void check(boolean cond) {if (cond) pass(); else fail();}
    static void check(boolean cond, String m) {if (cond) pass(); else fail(m);}
    static void equal(Object x, Object y) {
        if (x == null ? y == null : x.equals(y)) pass();
        else fail(">'" + x + "'<" + " not equal to " + "'" + y + "'");}

    public static void main(String[] args) throws Throwable {
        try {realMain(args);} catch (Throwable t) {unexpected(t);}
        System.out.printf("%nPassed = %d, failed = %d%n%n", passed, failed);
        if (failed > 0) throw new AssertionError("Some tests failed");}
    interface Fun {void f() throws Throwable;}
    static void THROWS(Class<? extends Throwable> k, Fun... fs) {
        for (Fun f : fs)
            try { f.f(); fail("Expected " + k.getName() + " not thrown"); }
            catch (Throwable t) {
                if (k.isAssignableFrom(t.getClass())) pass();
                else unexpected(t);}}

    static boolean isLocked(final Object monitor, final long millis) throws InterruptedException {
        return new Thread() {
            volatile boolean unlocked;

            @Override
            public void run() {
                synchronized (monitor) { unlocked = true; }
            }

            boolean isLocked() throws InterruptedException {
                start();
                join(millis);
                return !unlocked;
            }
        }.isLocked();
    }
}

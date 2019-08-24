package extraUtil;

import javax.tools.*;
import java.io.File;
import java.io.IOException;

public class JavaCodeUtil {

    public static boolean compile(File[] files) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, null, null);
        Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(files);
        JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, diagnostics, null, null, compilationUnits);
        boolean success = task.call();
        fileManager.close();
        return success;
    }

    public static void execute(File file) throws IOException {
        String location = file.getPath().replace(file.getName(), "");
        String osName = System.getProperty("os.name").toLowerCase();
        String executable = file.getName().replace(".java", "");

        if (osName.contains("linux")) {
            String[] command = {"xterm", "-hold", "-e", "java", "-cp", location, executable};
            Runtime.getRuntime().exec(command);
        }
    }
}

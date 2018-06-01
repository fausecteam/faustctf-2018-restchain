import java.lang.reflect.Method;

public class RunSelfTest {
	public static void main(String[] args) throws Exception {
		Class<?> cls = Class.forName("net.faustctf._2018.restchain.SelfTest");
		Method method = cls.getMethod("main", (new String[0]).getClass());
		System.out.println(method);
		method.setAccessible(true);
		method.invoke(null, new Object[] {args});
	}
}

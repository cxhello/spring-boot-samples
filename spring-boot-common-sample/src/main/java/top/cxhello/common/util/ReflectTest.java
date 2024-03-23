package top.cxhello.common.util;

import top.cxhello.common.entity.Client;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class ReflectTest {

    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException, NoSuchFieldException {
        /**
         * 获取 TargetObject 类的 Class 对象并且创建 TargetObject 类实例
         */
        Class<?> targetClass = Class.forName("top.cxhello.common.entity.Client");
        Client info = (Client) targetClass.newInstance();
        /**
         * 获取 TargetObject 类中定义的所有方法
         */
        Method[] methods = targetClass.getDeclaredMethods();
        for (Method method : methods) {
            //System.out.println(method.getName());
        }

        /**
         * 获取指定方法并调用
         */
        Method setClientId = targetClass.getDeclaredMethod("setClientId", Long.class);

        setClientId.invoke(info, 666L);

        Method getClientId = targetClass.getDeclaredMethod("getClientId");
        getClientId.invoke(info);


        /**
         * 获取指定参数并对参数进行修改
         */
        Field field = targetClass.getDeclaredField("clientId");
        //为了对类中的参数进行修改我们取消安全检查
        field.setAccessible(true);
        field.set(info, 777L);

        /**
         * 调用 private 方法
         */
        Method getClientId1 = targetClass.getDeclaredMethod("getClientId");
        //为了调用private方法我们取消安全检查
        getClientId1.setAccessible(true);
        getClientId1.invoke(info);
    }

}

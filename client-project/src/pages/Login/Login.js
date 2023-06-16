import { Button, Input, Form, notification } from "antd";
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { useState } from "react";
import Axios from "axios";
import Cookies from "js-cookie";
import "./Login.scss"

export const Login = () => {
  const [data, setData] = useState({ email: "", password: "" });

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await Axios.post(
        "http://localhost:3200/api/v1/auth/login",
        data
      );
      if (response.status === 200) {
        Cookies.set("auth", response.data.access, { expires: 7 });
        window.location.href = "http://localhost:3000/home";
      }
    } catch (error) {
      console.error("Error al obtener datos:", error);
      notification.error({
        message: 'Correo o Contraseña invalida',
        description: 'Verifique su correo y contraseña',
        placement: 'bottomRight'
      });
    }
  };

  return (
    <form onSubmit={handleSubmit} name="normal_login" className="login-form">
      <Form.Item name="email">
      <Input prefix={<UserOutlined/>} value={data.email} placeholder="Email" onChange={(e) => setData({ ...data, email: e.target.value })} />
      </Form.Item>
      <Form.Item name="password">
      <Input prefix={<LockOutlined/>} type="password" placeholder="Password" value={data.password} onChange={(e) => setData({ ...data, password: e.target.value })} />
      </Form.Item>
      <Form.Item>
        <Button type="primary" htmlType="submit" className="login-form-button">
          Log in
        </Button>
      </Form.Item>
    </form>
  );
};

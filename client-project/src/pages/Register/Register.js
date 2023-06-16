import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Form, Input, Select, notification } from 'antd';
import { useEffect, useState } from 'react';
import Axios from 'axios';
import './Register.scss'
import { useNavigate } from "react-router-dom";

const { Option } = Select;

export const Register = () => {
  const navigate = useNavigate();
  const [data, setData] = useState({
    firstname: '',
    lastname: '',
    email: '',
    password: '',
    departamento: '',
    municipio: ''
  });
  const [municipios, setMunicipios] = useState([]);
  const [departamentos, setDepartamentos] = useState([]);

  useEffect(() => {
    getDepartamentos();
  }, []);

  const getDepartamentos = async () => {
    try {
      const response = await Axios.get('http://localhost:3200/api/v1/departamentos-municipios');

      const uniqueData = response.data.reduce((accumulator, currentObject) => {
        const existingObject = accumulator.find((item) => item.departamento === currentObject.departamento);
        if (!existingObject) {
          return accumulator.concat(currentObject);
        } else {
          return accumulator;
        }
      }, []);

      setDepartamentos(uniqueData);
    } catch (error) {
      console.error('Error al obtener datos:', error);
    }
  };

  const handleSubmit = async (values) => {
    try {
      const response = await Axios.post('http://localhost:3200/api/v1/auth/register', values);
      console.log(response);
      notification.success({
        message: 'Usuario creado correctamente',
        description: 'Registro Exitoso',
        placement: 'bottomRight'
      });
      navigate("/Login");
    } catch (error) {
      console.error('Error al obtener datos:', error);
      notification.error({
        message: 'Usuario no registrado',
        description: 'Revise los datos, Algun dato esta erroneo',
        placement: 'bottomRight'
      });
    }
  };

  const handleSelectChange = async (name, value) => {
    setData({ ...data, [name]: value });

    if (name === 'departamento') {
      try {
        const response = await Axios.get(`http://localhost:3200/api/v1/departamentos-municipios?departamento=${value}`);
        setMunicipios(response.data);
        setData({ ...data, municipio: '' });
      } catch (error) {
        console.error('Error al obtener datos:', error);
      }
    }
  };

  return (
    <Form onFinish={handleSubmit} name="normal_login" className="register-form">
      <Form.Item name="firstname">
        <Input prefix={<UserOutlined />} placeholder="Firstname" onChange={(e) => setData({ ...data, firstname: e.target.value })} />
      </Form.Item>
      <Form.Item name="lastname">
        <Input prefix={<UserOutlined />} placeholder="Lastname" onChange={(e) => setData({ ...data, lastname: e.target.value })} />
      </Form.Item>
      <Form.Item name="email">
        <Input prefix={<UserOutlined />} placeholder="Email" onChange={(e) => setData({ ...data, email: e.target.value })} />
      </Form.Item>
      <Form.Item name="password">
        <Input.Password prefix={<LockOutlined />} placeholder="Password" value={data.password} onChange={(e) => setData({ ...data, password: e.target.value })} />
      </Form.Item>

      <Form.Item name="departamento">
        <Select placeholder="Seleccione el departamento" onChange={(value) => handleSelectChange('departamento', value)}>
          {departamentos.map((item, index) => (
            <Option key={index} value={item.departamento}>
              {item.departamento}
            </Option>
          ))}
        </Select>
      </Form.Item>
      <Form.Item name="municipio">
        <Select placeholder="Seleccione el municipio" onChange={(value) => handleSelectChange('municipio', value)} disabled={municipios.length === 0}>
          {municipios.map((item, index) => (
            <Option key={index} value={item.municipio}>
              {item.municipio}
            </Option>
          ))}
        </Select>
      </Form.Item>

      <Form.Item>
        <Button type="primary" htmlType="submit" className="register-form-button">
          Register
        </Button>
      </Form.Item>
    </Form>
  );
};

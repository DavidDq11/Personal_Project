import React from "react";
import { Button, Modal } from "antd";
import { LogoutOutlined} from "@ant-design/icons";
import { useNavigate } from "react-router-dom";

export const Logout = () => {
    const navigate = useNavigate();
    
    const handleLogout = () => {
        Modal.confirm({
            title: "Cerrar sesión",
            content: "¿Estás seguro de que quieres cerrar sesión?",
            onOk: () => {
                console.log('Cerrando sesión')
                navigate("/");
            },
        });
    };
    return (
        <Button type="link" onClick={handleLogout}>
         <LogoutOutlined/>
        </Button>
    );
};
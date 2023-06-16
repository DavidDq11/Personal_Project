import React from "react";
import Logo from "../../../assets/img/png/Logo.jpg";
import "./TopRegister.scss";
import { Button } from "antd";
import { Link } from "react-router-dom";

export const TopRegister = () => {
  return (
    <div className="top-register">
      <div className="top-register__left">
      <Link to="/">
          <img className="top-register__left__logo" src={Logo} alt="Logo"></img>
      </Link>
      </div>
      <div className="top-register__right">
        <Link to="/Register">
          <Button className="registrarse">Registrarse</Button>
        </Link>
        <Link to="/Login">
          <Button className="ingresar">Ingresar</Button>
        </Link>
      </div>
    </div>
  );
};

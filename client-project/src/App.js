/* rafce */
import "./App.scss"
import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import AllRoutesProject from './config/routes';
import Axios from 'axios';

const App = () => {

  /* Conexion al servidor */
  const [data, setData] = useState();
  const getData = async () => {
    try {
      const response = await Axios.get("http://localhost:3200/api/v1/auth");
      setData(response.data);
    } catch (error) {
      console.error("Error al obtener datos:", error);
    }
  };
  useEffect(()=>{
    getData()
  },[]);

  return (
    <BrowserRouter>
    <div>{data}</div>
      <Routes>
        {AllRoutesProject.map((route, index)=>(
          <Route
            key={index}
            path={route.path}
            element={
              <route.layout>
                <route.component/>
              </route.layout>
            }
            />
        ))}
      </Routes>
    </BrowserRouter>
  )
}

export default App
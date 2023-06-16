const bcrypt = require("bcryptjs");
const User = require("../models/user");
const jwt = require("../utils/jwt");
const departamentoMunicipio = require("../models/departamentoMunicipio");


/* Función que permite el registro de un usuario nuevo en el sistema */
const register = async (req, res) => {
    const { firstname, lastname, email, password, departamento, municipio } = req.body;
    if (!email) return res.status(400).send({ msg: "El email es requerido" });
    if (!departamento) return res.status(400).send({ msg: "El departamento es requerido" });
    if (!municipio) return res.status(400).send({ msg: "El municipio es requerido" });
    if (!password) return res.status(400).send({ msg: "La contraseña es requerido" });

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(password, salt);

    const user = new User({
        firstname,
        lastname,
        email: email.toLowerCase(),
        role: "user",
        active: true,
        password: hashPassword,
        departamento,
        municipio,
    });

    try {
        const userStorage = await user.save();
        res.status(201).send(userStorage);
    } catch (error) {
        res.status(400).send({ msg: "Error al crear el usuario" });
    }
};

/* Función que permite iniciar sesión */

const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
        throw new Error("El email y la contraseña son obligatorios");
        }
        const emailLowerCase = email.toLowerCase();
        const userStore = await User.findOne({ email: emailLowerCase }).exec();
        if (!userStore) {
        throw new Error("El usuario no existe");
        }
        const check = await bcrypt.compare(password, userStore.password);
        if (!check) {
        throw new Error("Contraseña incorrecta");
        }
        if (!userStore.active) {
        throw new Error("Usuario no autorizado o no activo");
        }
        res.status(200).send({
        access: jwt.createAccessToken(userStore),
        refresh: jwt.createRefreshToken(userStore),
        });
    } catch (error) {
        res.status(400).send({ msg: error.message });
    }
};

function refreshAccessToken(req, res) {
    const { token } = req.body;
    if (!token) res.status(400).send({ msg: "Token requerido" });
    const { user_id } = jwt.decoded(token);
    User.findOne({ _id: user_id }, (error, userStorage) => {
        if (error) {
        res.status(500).send({ msg: "Error del servidor" });
        } else {
        res.status(200).send({
            accessToken: jwt.createAccessToken(userStorage),
        });
        }
    });
}
const getDepartamentos = async (req, res) => {
    try {
        const departamentos = await departamentoMunicipio.find(
        {},
        { departamento: 1, _id: 0 }
        );
        const nombresDepartamentos = departamentos.map((item) => item.departamento);
        res.status(200).send(nombresDepartamentos);
    } catch (error) {
        res.status(500).send({ msg: "Error al obtener los departamentos" });
    }
};

const getMunicipios = async (req, res) => {
    const departamento = req.params.departamento;
    try {
        const municipios = await departamentoMunicipio.find(
        { departamento },
        { municipio: 1, _id: 0 }
    );
    const nombresMunicipios = municipios.map((item) => item.municipio);
    res.status(200).send(nombresMunicipios);
    } catch (error) {
        res.status(500).send({ msg: "Error al obtener los municipios" });
    }
};


module.exports = {
    register,
    login,
    refreshAccessToken,
    getDepartamentos,
    getMunicipios,
};
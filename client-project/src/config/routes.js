import { GeneralLayout } from "../layouts/GeneralLayout/GeneralLayout";
import { AdminHome } from "../pages/Admin/AdminHome";
import { SignIn } from "../pages/Admin/SignIn";
import { Contact } from "../pages/General/Contact";
import { Home } from "../pages/General/Home";
import { ListServices } from "../pages/Servicesmenu/ListServices";
import { NewServices } from "../pages/Servicesmenu/NewServices";
import { NotFound } from "../pages/General/NotFound/NotFound";
import { RegisterAndLogin } from "../layouts/RegisterAndLogin/RegisterAndLogin";
import { Login } from "../pages/Login/Login";
import { Register } from "../pages/Register/Register";
import { Initial } from "../pages/Initial/Initial";

const AdminRoutes = [
  { path: "/admin", component: AdminHome, layout: GeneralLayout },
  { path: "/admin/sign-in", component: SignIn, layout: GeneralLayout },
];
const GeneralRoutes = [
  { path: "/home", component: Home, layout: GeneralLayout },
  { path: "/contact", component: Contact, layout: GeneralLayout },
  { path: "*", component: NotFound, layout: GeneralLayout },
  { path: "/services/list", component:ListServices , layout: GeneralLayout },
  { path: "/services/new", component:NewServices, layout: GeneralLayout},
  { path: "/login", component: Login, layout: RegisterAndLogin },
  { path: "/register", component: Register, layout: RegisterAndLogin},
  { path: "/", component: Initial, layout: RegisterAndLogin}
];

const AllRoutesProject = [...AdminRoutes, ...GeneralRoutes];
export default AllRoutesProject;

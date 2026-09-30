import { Outlet } from "react-router-dom";
import Sidebar from "../components/layout/Sidebar";
import TopHeader from "../components/layout/TopHeader";
import "./MainLayout.css";

export default function MainLayout() {
  return (
    <div className="main-layout">
      <Sidebar />
      <div className="main-layout__body">
        <TopHeader />
        <main className="main-layout__content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

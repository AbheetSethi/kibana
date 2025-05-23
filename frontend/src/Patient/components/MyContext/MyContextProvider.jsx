import React from "react";
import MyContext from "./MyContext";

const MyContextProvider = (props) => {
    const [pid, setPid] = React.useState('0');

    return (
        <MyContext.Provider value={{ pid, setPid }}>
            {props.children}
        </MyContext.Provider>
    );
};

export default MyContextProvider;

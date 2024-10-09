import React, { useEffect, useMemo, useState } from 'react';
import { FormatterDate, FormatterDateProps } from './Formatters';

export type FormatterConditionalDateProps = FormatterDateProps & {
    warn?: number,  // Expiry for warning level in seconds
    error?: number, // Expiry for error level in seconds
}

/**
 * 
 * @param props 
 * @returns 
 */
export function FormatterConditionalDate(props: FormatterConditionalDateProps): JSX.Element {

    let { className: paramClassname, warn, error, value } = props;

    let [now, setNow] = useState(new Date().getTime());
    
    let className = useMemo(()=>{
        let nowEpochSecs = Math.floor(now / 1000);
        let param = paramClassname || '';
        param = 'transition-colors ' + param;
        if(error && nowEpochSecs - error > value) return 'text-red-500 ' + param;
        if(warn && nowEpochSecs - warn > value) return 'text-yellow-400 ' + param;
        return paramClassname;
    }, [now, warn, error, value, paramClassname]);

    useEffect(()=>{
        // Refresh regularly
        let interval = setInterval(()=>{
            setNow(new Date().getTime());
        }, 5_000);
        () => clearInterval(interval);
    }, [setNow]);

    return (
        <FormatterDate value={props.value} format={props.format} timezone={props.timezone} className={className} />
    )

}

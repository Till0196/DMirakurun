/*
   Copyright 2026 kanreisa

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import * as React from "react";
import { useMemo } from "react";
import * as regexp from "../modules/regexp";
import {
    ProgramAttributeClassMap,
    ProgramAttributeMap,
    ProgramAttributeNormalizationMap,
} from "../modules/constants";
import { state } from "../modules/state";
import { Program } from "../../../api.d";

import "./ProgramTitle.sass";

type ProgramTitleProps = {
    program: Program;
};
export const ProgramTitle: React.FC<ProgramTitleProps> = ({ program }) => {
    // console.debug("components", "ProgramTitle");

    let name = program.name;
    if (!name) {
        if (program.relatedItems) {
            const isShared = program.relatedItems.some(item => item.type === "shared");
            if (isShared) {
                name = "(イベント共有)";
            } else {
                name = "(不明)";
            }
        } else {
            name = "(未定)";
        }
    }
    name = name.replace(regexp.squaredUnicode, "").replace(regexp.legacyAttributeFormat, "");

    const serviceIsFree = state.services.find(service =>
        service.networkId === program.networkId &&
        service.serviceId === program.serviceId
    )?.isFree;

    const attributes = useMemo(() => {
        const attrSet = new Set<keyof typeof ProgramAttributeMap>();
        const attributeSource = (program.name || "") + (program.description || "");
        if (attributeSource) {
            const items = [
                ...attributeSource.match(regexp.enclosedAttributeUnicode) || [],
                ...attributeSource.match(regexp.legacyAttributeFormat) || [],
            ];
            for (const item of items) {
                const normalizedItem = item.replace(/[\[\]()［］]/g, "").normalize("NFKC");
                const attrKey = ProgramAttributeNormalizationMap[normalizedItem] || normalizedItem;
                if (attrKey === "無" && serviceIsFree === true) {
                    // SDT/MH-SDT が通常無料と示す公共放送・無料放送では [無] を省略する。
                    continue;
                }
                if (ProgramAttributeMap[attrKey]) {
                    attrSet.add(attrKey as any);
                }
            }
        }

        // 通常有料のサービスでEITが無料と示す番組は、無料開放として表示する。
        if (program.isFree && serviceIsFree === false) {
            attrSet.add("無");
        }

        return [...attrSet];
    }, [program.name, program.description, program.isFree, serviceIsFree]);

    const labels = useMemo(() => {
        const pre: JSX.Element[] = [];
        const post: JSX.Element[] = [];

        for (const attribute of attributes) {
            const label = (
                <span key={`attribute-${attribute}`}
                    className={`attribute bg-attribute-${ProgramAttributeClassMap[attribute]}`}
                    title={ProgramAttributeMap[attribute]}>
                    {attribute}
                </span>
            );

            if (["新", "再", "終", "生"].includes(attribute)) {
                pre.push(label);
            } else {
                post.push(label);
            }
        }

        return { pre, post };
    }, [attributes]);

    return (
        <span className="component-program-title">
            {labels.pre}
            <span className="name" title={program.name}>{name}</span>
            {labels.post}
        </span>
    );
};

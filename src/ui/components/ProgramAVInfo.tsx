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
import { langMap, audioModeDetailMap, audioModeMap } from "../modules/constants";
import {
    ProgramVideo,
    ProgramAudio,
    ProgramVideoTransferCharacteristics,
} from "../../../api.d";

import "./ProgramAVInfo.sass";

type ProgramAVInfoProps = {
    video: ProgramVideo;
    audios: ProgramAudio[];
};

const transferCharacteristicsMap: Record<ProgramVideoTransferCharacteristics, string> = {
    bt709: "BT.709",
    iec61966: "IEC 61966",
    bt2020: "BT.2020",
    "bt2100-pq": "BT.2100 PQ",
    "bt2100-hlg": "BT.2100 HLG",
};

export const ProgramAVInfo: React.FC<ProgramAVInfoProps> = ({ video, audios }) => {
    // console.debug("components", "ProgramAVInfo");

    const labels: JSX.Element[] = [];

    if (video) {
        labels.push(<span key="video.resolution" className="video resolution">{video.resolution}</span>);
        if (video.frameRate) {
            labels.push(<span key="video.frameRate" className="video frame-rate">{video.frameRate}fps</span>);
        }
        if (video.transferCharacteristics) {
            labels.push(
                <span key="video.transferCharacteristics" className="video transfer-characteristics">
                    {transferCharacteristicsMap[video.transferCharacteristics]}
                </span>
            );
        }
    }

    if (audios) {
        let count = 0;
        for (const audio of audios) {
            const trackPrefix = count === 0 ? "主" : "副";
            const type8 = audio.componentType.toString(2).padStart(8, "0");

            const modeKey = type8.slice(-5);
            const mode = audioModeMap[modeKey] || "不明なモード";
            const modeDetail = audioModeDetailMap[modeKey];
            const lang = audio.langs.map(lang => langMap[lang]).join("＋");

            labels.push(
                <span key={`audios.${count}`} className="audio" title={modeDetail}>
                    {audios.length > 1 && <>{trackPrefix}:&nbsp;</>}
                    {mode}
                    {lang !== "日本語" && <>&nbsp;/&nbsp;{lang}</>}
                </span>
            );
            count++;
        }
    }

    return (
        <div className="component-program-av-info">
            {labels}
        </div>
    );
};

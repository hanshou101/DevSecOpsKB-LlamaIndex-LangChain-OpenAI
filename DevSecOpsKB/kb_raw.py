from dataclasses import dataclass

from llama_index import SimpleDirectoryReader, LLMPredictor, PromptHelper, StorageContext, ServiceContext, GPTVectorStoreIndex, load_index_from_storage
from langchain.chat_models import ChatOpenAI
import gradio as gr
# import sys
import os
#
#
#
import openai
import time

from DevSecOpsKB.my_helper import get_time

os.environ["OPENAI_API_KEY"] = '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'
openai.api_key = os.getenv('OPENAI_API_KEY')
openai.proxy = "http://127.0.0.1:59998"


@dataclass
class Cfg:
    max_input_size: int
    num_outputs: int
    max_chunk_overlap: int
    chunk_size_limit: int


def get_cfg():

    """
    20+、30+秒


    """
    a = Cfg(
        4096,
        512,
        20,
        600
    )

    """
    效果较好
    
    54+秒
    60+秒
            质量较好
    73+秒
            质量略弱
    
    """
    b = Cfg(
        4096,
        512 * 2,
        20,
        600
    )

    """
    大概80秒。
    """
    c = Cfg(
        4096,
        512 * 3,
        20,
        600
    )

    """
    100+秒后，Got a larger chunk overlap 
    """
    d = Cfg(
        4096,
        512 * 4,
        20,
        600
    )
    """
    60+秒，能出。
            但文字效果，和【b】也差不多？
    90+秒，能出
            但文字效果，和【b】也差不多？？？            
    """
    e = Cfg(
        4096,
        512 * 4,
        30,
        900,
    )

    """
    50+秒，效果还是很棒的。
    """
    f = Cfg(
        4096,
        512 * 2,
        10,
        300,
    )

    """
    55+秒，效果还是很棒的。
            效果，反而跌下去了？？？
            多试了几次，效果确实变差了
    """
    g = Cfg(
        4096,
        512 * 2,
        30,
        100,
    )

    # return a
    return b


def create_service_context():
    # constraint parameters
    cfg = get_cfg()

    # allows the user to explicitly set certain constraint parameters
    prompt_helper = PromptHelper(cfg.max_input_size, cfg.num_outputs, cfg.max_chunk_overlap, chunk_size_limit=cfg.chunk_size_limit)

    # LLMPredictor is a wrapper class around LangChain's LLMChain that allows easy integration into LlamaIndex
    llm_predictor = LLMPredictor(llm=ChatOpenAI(
        # temperature=0.2,
        # temperature=0.0,
        # temperature=0.7,
        temperature=0.3,
        model_name="gpt-3.5-turbo", max_tokens=cfg.num_outputs))

    # constructs service_context
    service_context = ServiceContext.from_defaults(llm_predictor=llm_predictor, prompt_helper=prompt_helper)
    return service_context


def data_ingestion_indexing(directory_path):
    # loads data from the specified directory path
    documents = SimpleDirectoryReader(directory_path).load_data()

    # when first building the index
    index = GPTVectorStoreIndex.from_documents(
        documents, service_context=create_service_context()
    )

    # persist index to disk, default "storage" folder
    index.storage_context.persist()

    return index

@get_time
def data_querying(input_text):
    # rebuild storage context
    storage_context = StorageContext.from_defaults(persist_dir="./storage")

    # loads index from storage
    index = load_index_from_storage(storage_context, service_context=create_service_context())

    # queries the index with the input text
    response = index.as_query_engine().query(input_text)

    return response.response


iface = gr.Interface(fn=data_querying,
                     inputs=gr.components.Textbox(lines=7, label="Enter your question"),
                     outputs="text",
                     title="Wenqi's Custom-trained DevSecOps Knowledge Base")

print("""
老版本测试

【】

请为我总结，在【知识库】中，所有和【sql注入攻击】相关的信息。

要求：
① 尽可能详细
② 用中文进行表达
③ 如果有链接，请附带相关的链接进行显示。
④ 对于找到的每个知识点，除了列出重点标题信息之外，请展开详细做逐一介绍。

基本，在【20+秒】左右。


————————————————————————————

结果，基本有一个极限啊：

最基础版的。到了一定程度，【temperature】设置为【0.0】，都无法更准确了。    


————————————————————————————

尝试，将【num_outputs】翻倍

耗时，基本在【40秒+】出头。
好处是，基本上，    都是稳定能成功的。


而且，结果，和【目标指定的  SQL注入攻击】，都是相贴近的。


————————————————————————————

尝试，将【temperature】，调整为【0.7】

大概，35%的内容，都偏离了

————————————————————————————

尝试，将【temperature】，调整为【1.0】

有的全篇，都略有点相关联；    有的，就是通篇不着调

————————————————————————————

尝试，将【temperature】，调整为【0.3】

结果：同时产生两篇，一篇看似非常靠谱；另一篇，看似很少靠谱。

第二次，两篇看上去，都还算靠谱。

此时，就还算均衡了；还算可以接受。

""")

# passes in data directory
index = data_ingestion_indexing("data_cn")
iface.launch(share=False)
